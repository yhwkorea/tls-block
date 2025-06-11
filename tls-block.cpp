#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <map>
#include <string>

using namespace std;

typedef unsigned short u16;
static u16 checksum(u16* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)(~sum);
}

// Parse SNI from a single-record TLS ClientHello
static string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (len < 5 + rec_len) return "";
    size_t pos = 5;
    if (pos + 4 > len || data[pos] != 0x01) return "";
    uint32_t hs_len = (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
    pos += 4;
    if (pos + hs_len > len) return "";
    pos += 2 + 32;
    if (pos >= len) return "";
    uint8_t sid_len = data[pos++];
    pos += sid_len;
    if (pos + 2 > len) return "";
    uint16_t cs_len = (data[pos] << 8) | data[pos+1]; pos += 2 + cs_len;
    if (pos >= len) return "";
    uint8_t comp_len = data[pos++]; pos += comp_len;
    if (pos + 2 > len) return "";
    uint16_t ext_len = (data[pos] << 8) | data[pos+1]; pos += 2;
    size_t end_ext = pos + ext_len;
    while (pos + 4 <= end_ext && pos + 4 <= len) {
        uint16_t t = (data[pos] << 8) | data[pos+1];
        uint16_t l = (data[pos+2] << 8) | data[pos+3]; pos += 4;
        if (t == 0x0000 && pos + l <= end_ext) {
            pos += 2; // list length
            pos += 1; // name type
            if (pos + 2 > end_ext) return "";
            uint16_t name_len = (data[pos] << 8) | data[pos+1]; pos += 2;
            if (pos + name_len > end_ext) return "";
            return string((char*)(data + pos), name_len);
        }
        pos += l;
    }
    return "";
}

// Flow key: 4-tuple
struct FlowKey {
    uint32_t src, dst;
    uint16_t sport, dport;
    bool operator<(const FlowKey& o) const {
        return tie(src,dst,sport,dport) < tie(o.src,o.dst,o.sport,o.dport);
    }
};

// Reassembly buffer
struct Reassembly {
    uint32_t base_seq{};
    size_t expected{};
    vector<uint8_t> buf;
    bool in_progress{};
};

// Forward injection: full Ethernet frame via pcap_sendpacket
static void inject_forward_rst(pcap_t* handle,
    const u_char* orig,
    const struct iphdr* iph_orig,
    const struct tcphdr* tcph_orig,
    int data_len,
    const uint8_t mac[6]) {
    int eth_sz = sizeof(ether_header);
    int ip_sz  = iph_orig->ihl * 4;
    int tcp_sz = tcph_orig->th_off * 4;
    int pkt_sz = eth_sz + ip_sz + tcp_sz;
    vector<u_char> pkt(pkt_sz);
    memcpy(pkt.data(), orig, pkt_sz);
    auto* eth = (ether_header*)pkt.data();
    memcpy(eth->ether_shost, mac, 6);
    auto* iph = (iphdr*)(pkt.data() + eth_sz);
    iph->tot_len = htons(ip_sz + tcp_sz);
    iph->check   = 0;
    iph->check   = checksum((u16*)iph, ip_sz);
    auto* tcph = (tcphdr*)(pkt.data() + eth_sz + ip_sz);
    tcph->seq     = htonl(ntohl(tcph_orig->seq) + data_len);
    tcph->ack_seq = tcph_orig->ack_seq;
    tcph->rst     = 1;
    tcph->ack     = 1;
    tcph->th_off  = tcp_sz / 4;
    tcph->check   = 0;
    struct { uint32_t src,dst; uint8_t zero,proto; uint16_t len; } pseudo;
    pseudo.src   = iph->saddr;
    pseudo.dst   = iph->daddr;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len   = htons(tcp_sz);
    vector<u_char> buf2(sizeof(pseudo) + tcp_sz);
    memcpy(buf2.data(), &pseudo, sizeof(pseudo));
    memcpy(buf2.data() + sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf2.data(), buf2.size());
    pcap_sendpacket(handle, pkt.data(), pkt_sz);
}

// Backward injection: IP/TCP only via raw socket
static void inject_backward_rst(const struct iphdr* iph_orig,
    const struct tcphdr* tcph_orig,
    int data_len) {
    int ip_sz  = iph_orig->ihl * 4;
    int tcp_sz = tcph_orig->th_off * 4;
    int pkt_sz = ip_sz + tcp_sz;
    vector<u_char> pkt(pkt_sz);
    memcpy(pkt.data(), iph_orig, ip_sz);
    memcpy(pkt.data() + ip_sz, tcph_orig, tcp_sz);
    auto* iph = (iphdr*)pkt.data();
    iph->saddr   = iph_orig->daddr;
    iph->daddr   = iph_orig->saddr;
    iph->tot_len = htons(pkt_sz);
    iph->check   = 0;
    iph->check   = checksum((u16*)iph, ip_sz);
    auto* tcph = (tcphdr*)(pkt.data() + ip_sz);
    tcph->source   = tcph_orig->dest;
    tcph->dest     = tcph_orig->source;
    tcph->seq      = tcph_orig->ack_seq;
    tcph->ack_seq  = htonl(ntohl(tcph_orig->seq) + data_len);
    tcph->rst      = 1;
    tcph->ack      = 1;
    tcph->th_off   = tcp_sz / 4;
    tcph->check    = 0;
    struct { uint32_t src,dst; uint8_t zero,proto; uint16_t len; } pseudo;
    pseudo.src   = iph->saddr;
    pseudo.dst   = iph->daddr;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len   = htons(tcp_sz);
    vector<u_char> buf2(sizeof(pseudo) + tcp_sz);
    memcpy(buf2.data(), &pseudo, sizeof(pseudo));
    memcpy(buf2.data() + sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf2.data(), buf2.size());
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1; setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dst{}; dst.sin_family = AF_INET; dst.sin_addr.s_addr = iph->daddr;
    sendto(sd, pkt.data(), pkt_sz, 0, (struct sockaddr*)&dst, sizeof(dst));
    close(sd);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        cerr << "syntax: tls-block <interface> <pattern>\n";
        return 1;
    }
    char* dev = argv[1];
    string pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) { cerr << errbuf << "\n"; return 1; }
    pcap_set_immediate_mode(handle, 1);
    struct bpf_program fp;
    pcap_compile(handle, &fp, "tcp port 443", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    // retrieve MAC address
    uint8_t mac[6];
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);

    map<FlowKey, Reassembly> flows;
    while (true) {
        struct pcap_pkthdr* hdr;
        const u_char* p;
        if (pcap_next_ex(handle, &hdr, &p) <= 0) continue;
        auto* eth = (ether_header*)p;
        if (ntohs(eth->ether_type) != ETH_P_IP) continue;
        auto* iph = (iphdr*)(p + sizeof(ether_header));
        if (iph->protocol != IPPROTO_TCP) continue;
        int ip_len = iph->ihl * 4;
        auto* tcph = (tcphdr*)(p + sizeof(ether_header) + ip_len);
        int tcp_len = tcph->th_off * 4;
        int dlen = ntohs(iph->tot_len) - ip_len - tcp_len;
        if (dlen <= 0) continue;
        const uint8_t* data = p + sizeof(ether_header) + ip_len + tcp_len;

        FlowKey key{iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest)};
        auto& r = flows[key];
        uint32_t seq = ntohl(tcph->seq);

        // single-packet
        if (!r.in_progress) {
            string sni = parse_sni(data, dlen);
            if (!sni.empty() && sni.find(pattern) != string::npos) {
                inject_forward_rst(handle, p, iph, tcph, dlen, mac);
                inject_backward_rst(iph, tcph, dlen);
                cout << "[+] Blocked: " << sni << endl;
                continue;
            }
            if (dlen >= 5 && data[0]==0x16) {
                uint16_t rec = (data[3]<<8)|data[4];
                r.base_seq = seq;
                r.expected = 5 + rec;
                r.buf.insert(r.buf.end(), data, data + dlen);
                r.in_progress = true;
            }
        } else {
            if (seq == r.base_seq + r.buf.size()) {
                r.buf.insert(r.buf.end(), data, data + dlen);
                if (r.buf.size() >= r.expected) {
                    string sni = parse_sni(r.buf.data(), r.buf.size());
                    flows.erase(key);
                    if (!sni.empty() && sni.find(pattern) != string::npos) {
                        inject_forward_rst(handle, p, iph, tcph, r.expected, mac);
                        inject_backward_rst(iph, tcph, r.expected);
                        cout << "[+] Reassembled & Blocked: " << sni << endl;
                    }
                }
            } else flows.erase(key);
        }
    }
    pcap_close(handle);
    return 0;
}
