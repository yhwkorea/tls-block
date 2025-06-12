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
#include <unordered_map>
#include <vector>
#include <string>
#include <iostream>
using namespace std;

typedef unsigned short u16;

void usage() {
    printf("syntax : tls-block <interface> <server_name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

static u16 checksum(u16* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)(~sum);
}

// Parse SNI from single-record TLS ClientHello
// https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FI5TLu%2FbtrBRoSgSI2%2FVRgHO2rNOljLsP9IsAYwaK%2Fimg.jpg
static string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (len < (size_t)5 + rec_len) return "";
    size_t pos = 5;
    if (pos + 4 > len || data[pos] != 0x01) return "";
    uint32_t hs_len = (data[pos+1]<<16)|(data[pos+2]<<8)|data[pos+3];
    pos += 4;
    if (pos + hs_len > len) return "";
    pos += 2 + 32; // version + random
    if (pos >= len) return "";
    uint8_t sid_len = data[pos++]; pos += sid_len;
    if (pos + 2 > len) return "";
    uint16_t cs_len = (data[pos]<<8)|data[pos+1]; pos += 2 + cs_len;
    if (pos >= len) return "";
    uint8_t comp_len = data[pos++]; pos += comp_len;
    if (pos + 2 > len) return "";
    uint16_t ext_total = (data[pos]<<8)|data[pos+1]; pos += 2;
    size_t end_ext = pos + ext_total;
    while (pos + 4 <= end_ext && pos + 4 <= len) {
        uint16_t t = (data[pos]<<8)|data[pos+1];
        uint16_t l = (data[pos+2]<<8)|data[pos+3]; pos += 4;
        if (t == 0x0000 && pos + l <= end_ext) {
            pos += 2 + 1; // list length + name type
            uint16_t name_len = (data[pos]<<8)|data[pos+1]; pos += 2;
            if (pos + name_len <= end_ext)
                return string((char*)(data + pos), name_len);
            else
                return "";
        }
        pos += l;
    }
    return "";
}

struct FlowKey {
    uint32_t src, dst;
    uint16_t sport, dport;
    bool operator==(const FlowKey& o) const {
        return src==o.src && dst==o.dst && sport==o.sport && dport==o.dport;
    }
};

struct FlowKeyHash {
    size_t operator()(FlowKey const& k) const noexcept {
        return k.src ^ (k.dst<<1) ^ ((size_t)k.sport<<16) ^ ((size_t)k.dport<<1);
    }
};

struct Reassembly {
    uint32_t base_seq{};
    size_t expected_len{};
    vector<uint8_t> buf;
    bool in_progress{};
};

// Fixed-size buffer for injection
static u_char outbuf[1500];

// Forward injection via pcap: full Ethernet frame
static void inject_forward_rst(pcap_t* handle,
    const u_char* orig,
    const iphdr* iph_orig,
    const tcphdr* tcph_orig,
    int data_len,
    const uint8_t mac[6]) {
    int eth_sz = sizeof(ether_header);
    int ip_sz  = iph_orig->ihl * 4;
    int tcp_sz = tcph_orig->th_off * 4;
    int pkt_sz = eth_sz + ip_sz + tcp_sz;

    memcpy(outbuf, orig, pkt_sz);
    auto* eth = (ether_header*)outbuf;
    memcpy(eth->ether_shost, mac, 6);

    auto* iph = (iphdr*)(outbuf + eth_sz);
    iph->tot_len = htons(ip_sz + tcp_sz);
    iph->check = 0;
    iph->check = checksum((u16*)iph, ip_sz);

    auto* tcph = (tcphdr*)(outbuf + eth_sz + ip_sz);
    tcph->seq = htonl(ntohl(tcph_orig->seq) + data_len);
    tcph->ack_seq = tcph_orig->ack_seq;
    tcph->rst = 1;
    tcph->ack = 1;
    tcph->th_off = tcp_sz/4;
    tcph->check = 0;

    struct { uint32_t src,dst; uint8_t zero,proto; uint16_t len; } pseudo;
    pseudo.src = iph->saddr;
    pseudo.dst = iph->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(tcp_sz);

    vector<u_char> buf2(sizeof(pseudo) + tcp_sz);
    memcpy(buf2.data(), &pseudo, sizeof(pseudo));
    memcpy(buf2.data()+sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf2.data(), buf2.size());

    pcap_sendpacket(handle, outbuf, pkt_sz);
}

// Backward injection via raw socket: IP/TCP only
static void inject_backward_rst(const iphdr* iph_orig,
    const tcphdr* tcph_orig,
    int data_len) {
    int ip_sz = iph_orig->ihl *4;
    int tcp_sz = tcph_orig->th_off *4;
    int pkt_sz = ip_sz + tcp_sz;

    vector<u_char> pkt(pkt_sz);
    memcpy(pkt.data(), iph_orig, ip_sz);
    memcpy(pkt.data()+ip_sz, tcph_orig, tcp_sz);

    auto* iph = (iphdr*)pkt.data();
    iph->saddr = iph_orig->daddr;
    iph->daddr = iph_orig->saddr;
    iph->tot_len = htons(pkt_sz);
    iph->check = 0;
    iph->check = checksum((u16*)iph, ip_sz);

    auto* tcph = (tcphdr*)(pkt.data()+ip_sz);
    tcph->source = tcph_orig->dest;
    tcph->dest = tcph_orig->source;
    tcph->seq = tcph_orig->ack_seq;
    tcph->ack_seq = htonl(ntohl(tcph_orig->seq)+data_len);
    tcph->rst = 1;
    tcph->ack = 1;
    tcph->th_off = tcp_sz/4;
    tcph->check = 0;

    struct { uint32_t src,dst; uint8_t zero,proto; uint16_t len; } pseudo;
    pseudo.src = iph->saddr;
    pseudo.dst = iph->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(tcp_sz);
    vector<u_char> buf2(sizeof(pseudo)+tcp_sz);
    memcpy(buf2.data(), &pseudo, sizeof(pseudo));
    memcpy(buf2.data()+sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf2.data(), buf2.size());

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one=1; setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_addr.s_addr=iph->daddr;
    sendto(sd, pkt.data(), pkt_sz, 0, (sockaddr*)&dst, sizeof(dst));
    close(sd);
}

int main(int argc, char** argv) {
    if (argc!=3) { usage(); return 1; }
    char* dev = argv[1];
    string pat = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1, errbuf);
    if (!handle) { cerr << errbuf << "\n"; return 1; }
    pcap_set_immediate_mode(handle, 1);
    struct bpf_program fp;
    pcap_compile(handle, &fp, "tcp dst port 443", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    // get MAC
    uint8_t mac[6];
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);

    unordered_map<FlowKey, Reassembly, FlowKeyHash> flows;
    flows.reserve(1024);

    while (true) {
        pcap_pkthdr* hdr;
        const u_char* pkt;
        if (pcap_next_ex(handle, &hdr, &pkt) <= 0) continue;
        auto* eth = (ether_header*)pkt;
        if (ntohs(eth->ether_type) != ETH_P_IP) continue;
        auto* iph = (iphdr*)(pkt + sizeof(ether_header));
        if (iph->protocol != IPPROTO_TCP) continue;
        int ip_len = iph->ihl * 4;
        auto* tcph = (tcphdr*)(pkt + sizeof(ether_header) + ip_len);
        int tcp_len = tcph->th_off * 4;
        int dlen = ntohs(iph->tot_len) - ip_len - tcp_len;
        if (dlen <= 0) continue;
        const uint8_t* data = (uint8_t*)tcph + tcp_len;

        FlowKey key{iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest)};
        auto& r = flows[key];
        uint32_t seq = ntohl(tcph->seq);

        if (!r.in_progress) {
            // single-packet SNI
            string sni = parse_sni(data, dlen);
            if (!sni.empty() && sni.find(pat) != string::npos) {
                inject_forward_rst(handle, pkt, iph, tcph, dlen, mac);
                inject_backward_rst(iph, tcph, dlen);
                cout << "[+] Blocked: " << sni << "\n";
                continue;
            }
            // start reassembly
            if (dlen >= 5 && data[0] == 0x16) {
                uint16_t rec = (data[3]<<8)|data[4];
                r.base_seq = seq;
                r.expected_len = 5 + rec;
                r.buf.clear();
                r.buf.reserve(r.expected_len);
                r.buf.insert(r.buf.end(), data, data + dlen);
                r.in_progress = true;
            }
        } else {
            // continue reassembly
            if (seq >= r.base_seq && seq < r.base_seq + r.expected_len) {
                size_t off = seq - r.base_seq;
                if (r.buf.size() < off + dlen) r.buf.resize(off + dlen);
                memcpy(r.buf.data() + off, data, dlen);
                if (r.buf.size() >= r.expected_len) {
                    string sni = parse_sni(r.buf.data(), r.buf.size());
                    flows.erase(key);
                    if (!sni.empty() && sni.find(pat) != string::npos) {
                        inject_forward_rst(handle, pkt, iph, tcph, r.expected_len, mac);
                        inject_backward_rst(iph, tcph, r.expected_len);
                        cout << "[+] Reassembled & Blocked: " << sni << "\n";
                    }
                }
            } else {
                flows.erase(key);
            }
        }
    }
    pcap_close(handle);
    return 0;
}
