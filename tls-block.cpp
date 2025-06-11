#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <map>
#include <string>

using namespace std;
typedef unsigned short u16;

// Compute IP/TCP checksum
u16 checksum(u16* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)~sum;
}

// Inject RST|ACK to server (L2 via pcap)
void inject_rst_to_server(pcap_t* handle, const u_char* orig,
                          const struct iphdr* ip_hdr, const struct tcphdr* tcp_hdr,
                          int data_len, const uint8_t mac[6]) {
    int eth_sz  = sizeof(struct ether_header);
    int ip_sz   = ip_hdr->ihl * 4;
    int tcp_sz  = tcp_hdr->th_off * 4;
    int pkt_sz  = eth_sz + ip_sz + tcp_sz;
    static u_char out[1600];
    memcpy(out, orig, pkt_sz);
    // Update source MAC
    struct ether_header* eh = (struct ether_header*)out;
    memcpy(eh->ether_shost, mac, 6);
    // IP header
    struct iphdr* iph = (struct iphdr*)(out + eth_sz);
    iph->tot_len = htons(ip_sz + tcp_sz);
    iph->check   = 0;
    iph->check   = checksum((u16*)iph, ip_sz);
    // TCP header
    struct tcphdr* tcph = (struct tcphdr*)(out + eth_sz + ip_sz);
    tcph->seq     = htonl(ntohl(tcp_hdr->seq) + data_len);
    tcph->ack_seq = tcp_hdr->ack_seq;
    tcph->rst     = 1;
    tcph->ack     = 1;
    tcph->doff    = tcp_hdr->th_off;
    tcph->check   = 0;
    // TCP checksum
    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo;
    pseudo.src   = iph->saddr;
    pseudo.dst   = iph->daddr;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len   = htons(tcp_sz);
    static u_char buf[1600];
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf, sizeof(pseudo) + tcp_sz);
    // send
    pcap_sendpacket(handle, out, pkt_sz);
}

// Inject RST|ACK to client (raw socket)
void inject_rst_to_client(const struct iphdr* ip_hdr, const struct tcphdr* tcp_hdr,
                           int data_len) {
    int ip_sz  = ip_hdr->ihl * 4;
    int tcp_sz = tcp_hdr->th_off * 4;
    int pkt_sz = ip_sz + tcp_sz;
    vector<uint8_t> pkt(pkt_sz);
    memcpy(pkt.data(), ip_hdr, ip_sz);
    memcpy(pkt.data() + ip_sz, tcp_hdr, tcp_sz);
    struct iphdr* iph = (struct iphdr*)pkt.data();
    iph->tot_len = htons(pkt_sz);
    iph->check   = 0;
    iph->check   = checksum((u16*)iph, ip_sz);
    struct tcphdr* tcph = (struct tcphdr*)(pkt.data() + ip_sz);
    tcph->seq     = tcp_hdr->ack_seq;
    tcph->ack_seq = htonl(ntohl(tcp_hdr->seq) + data_len);
    tcph->rst     = 1;
    tcph->ack     = 1;
    tcph->doff    = tcp_hdr->th_off;
    tcph->check   = 0;
    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo;
    pseudo.src   = iph->saddr;
    pseudo.dst   = iph->daddr;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len   = htons(tcp_sz);
    vector<uint8_t> buf(sizeof(pseudo) + tcp_sz);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf.data(), buf.size());
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = iph->daddr;
    sendto(sd, pkt.data(), pkt_sz, 0, (struct sockaddr*)&dst, sizeof(dst));
    close(sd);
}

// Extract SNI from TLS ClientHello
string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (len < (size_t)5 + rec_len) return "";
    size_t pos = 5;
    if (pos + 4 > len || data[pos] != 0x01) return "";
    uint32_t hs_len = (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
    pos += 4;
    if (pos + hs_len > len) return "";
    pos += 2 + 32;
    uint8_t sid_len = data[pos++]; pos += sid_len;
    uint16_t cs_len = (data[pos] << 8) | data[pos+1]; pos += 2 + cs_len;
    uint8_t comp_len = data[pos++]; pos += comp_len;
    uint16_t ext_total = (data[pos] << 8) | data[pos+1]; pos += 2;
    size_t end_ext = pos + ext_total;
    while (pos + 4 <= end_ext) {
        uint16_t ext_type = (data[pos] << 8) | data[pos+1];
        uint16_t ext_len  = (data[pos+2] << 8) | data[pos+3]; pos += 4;
        if (ext_type == 0x0000 && pos + ext_len <= end_ext) {
            pos += 2; // list length
            pos += 1; // name_type
            uint16_t name_len = (data[pos] << 8) | data[pos+1]; pos += 2;
            return string((char*)(data + pos), name_len);
        }
        pos += ext_len;
    }
    return "";
}

struct Flow { struct in_addr src, dst; uint16_t sport, dport;
    bool operator<(const Flow& o) const {
        if (src.s_addr != o.src.s_addr) return src.s_addr < o.src.s_addr;
        if (dst.s_addr != o.dst.s_addr) return dst.s_addr < o.dst.s_addr;
        if (sport != o.sport) return sport < o.sport;
        return dport < o.dport;
    }
};
struct Reassembly { uint32_t base_seq{}; vector<uint8_t> buf; size_t expected{}; bool got_len{}; };

int main(int argc, char* argv[]) {
    if (argc != 3) { cerr << "syntax: tls-block <interface> <pattern>\n"; return -1; }
    char* dev = argv[1];
    string pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65535, 1, -1, errbuf);
    if (!handle) { cerr << errbuf << endl; return -1; }
    pcap_set_immediate_mode(handle, 1);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 443", 1, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);

    map<Flow, Reassembly> flows;
    while (true) {
        struct pcap_pkthdr* hdr;
        const u_char* pkt;
        if (pcap_next_ex(handle, &hdr, &pkt) <= 0) continue;
        struct ether_header* eth = (struct ether_header*)pkt;
        if (ntohs(eth->ether_type) != ETH_P_IP) continue;
        struct iphdr* iph = (struct iphdr*)(pkt + sizeof(struct ether_header));
        if (iph->protocol != IPPROTO_TCP) continue;
        int ip_len = iph->ihl * 4;
        struct tcphdr* tcph = (struct tcphdr*)(pkt + sizeof(struct ether_header) + ip_len);
        int tcp_len = tcph->th_off * 4;
        int dlen = ntohs(iph->tot_len) - ip_len - tcp_len;
        if (dlen <= 0) continue;
        const uint8_t* data = pkt + sizeof(struct ether_header) + ip_len + tcp_len;

        Flow f{iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest)};
        auto& r = flows[f];
        uint32_t seq = ntohl(tcph->seq);

        if (!r.got_len) {
            if (dlen >= 5 && data[0] == 0x16) {
                uint16_t rec = (data[3] << 8) | data[4];
                r.base_seq = seq;
                r.expected = 5 + rec;
                r.got_len = true;
                r.buf.insert(r.buf.end(), data, data + dlen);
            }
        } else {
            if (seq == r.base_seq + r.buf.size()) {
                r.buf.insert(r.buf.end(), data, data + dlen);
                if (r.buf.size() >= r.expected) {
                    string sni = parse_sni(r.buf.data(), r.buf.size());
                    r.buf.clear(); r.got_len = false;
                    if (!sni.empty() && sni.find(pattern) != string::npos) {
                        uint8_t mac[6]; memcpy(mac, eth->ether_shost, 6);
                        inject_rst_to_server(handle, pkt, iph, tcph, r.expected, mac);
                        struct iphdr rip = *iph;
                        struct tcphdr rtc = *tcph;
                        rip.saddr = iph->daddr; rip.daddr = iph->saddr;
                        rtc.source = tcph->dest; rtc.dest = tcph->source;
                        rtc.seq = tcph->ack_seq; rtc.ack_seq = htonl(ntohl(tcph->seq) + r.expected);
                        inject_rst_to_client(&rip, &rtc, r.expected);
                        cout << "[+] TLS-blocked " << sni << endl;
                    }
                }
            } else flows.erase(f);
        }
    }
    pcap_close(handle);
    return 0;
}
