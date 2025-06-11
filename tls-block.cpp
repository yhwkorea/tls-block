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

// Inline SNI parsing
static string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (len < 5 + rec_len) return "";
    size_t pos = 5;
    if (data[pos] != 0x01) return "";
    pos += 4 + 32;
    if (pos + 1 > len) return "";
    uint8_t sid_len = data[pos++]; pos += sid_len;
    if (pos + 2 > len) return "";
    uint16_t cs_len = (data[pos] << 8) | data[pos+1]; pos += 2 + cs_len;
    if (pos + 1 > len) return "";
    uint8_t comp_len = data[pos++]; pos += comp_len;
    if (pos + 2 > len) return "";
    uint16_t ext_total = (data[pos] << 8) | data[pos+1]; pos += 2;
    size_t end_ext = pos + ext_total;
    while (pos + 4 <= end_ext) {
        uint16_t t = (data[pos] << 8) | data[pos+1];
        uint16_t l = (data[pos+2] << 8) | data[pos+3]; pos += 4;
        if (t == 0x0000 && pos + l <= end_ext) {
            pos += 2; pos += 1;
            if (pos + 2 > end_ext) return "";
            uint16_t name_len = (data[pos] << 8) | data[pos+1]; pos += 2;
            if (pos + name_len > end_ext) return "";
            return string((char*)(data + pos), name_len);
        }
        pos += l;
    }
    return "";
}

struct Flow { in_addr src, dst; uint16_t sport, dport;
    bool operator<(const Flow& o) const {
        if (src.s_addr != o.src.s_addr) return src.s_addr < o.src.s_addr;
        if (dst.s_addr != o.dst.s_addr) return dst.s_addr < o.dst.s_addr;
        if (sport != o.sport) return sport < o.sport;
        return dport < o.dport;
    }
};
struct Reassembly { uint32_t base_seq{}; vector<uint8_t> buf; size_t expected{}; bool in_progress{}; };

// Forward injection via pcap (L2 frame)
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
    struct {
        uint32_t src, dst; uint8_t zero, proto; uint16_t len;
    } pseudo{ iph->saddr, iph->daddr, 0, IPPROTO_TCP, htons(tcp_sz) };
    vector<u_char> buf2(sizeof(pseudo) + tcp_sz);
    memcpy(buf2.data(), &pseudo, sizeof(pseudo));
    memcpy(buf2.data() + sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf2.data(), buf2.size());
    pcap_sendpacket(handle, pkt.data(), pkt_sz);
}

// Backward injection via raw socket (IP/TCP only)
static void inject_backward_rst(const iphdr* iph_orig,
                                const tcphdr* tcph_orig,
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
    struct {
        uint32_t src, dst; uint8_t zero, proto; uint16_t len;
    } pseudo{ iph->saddr, iph->daddr, 0, IPPROTO_TCP, htons(tcp_sz) };
    vector<u_char> buf2(sizeof(pseudo) + tcp_sz);
    memcpy(buf2.data(), &pseudo, sizeof(pseudo));
    memcpy(buf2.data() + sizeof(pseudo), tcph, tcp_sz);
    tcph->check = checksum((u16*)buf2.data(), buf2.size());
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1; setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dst{}; dst.sin_family = AF_INET; dst.sin_addr.s_addr = iph->daddr;
    sendto(sd, pkt.data(), pkt_sz, 0, (sockaddr*)&dst, sizeof(dst));
    close(sd);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "syntax: tls-block <interface> <server>\n";
        return -1;
    }
    char* dev = argv[1]; string pattern = argv[2];
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65535, 1, -1, err);
    if (!handle) { cerr << err << endl; return -1; }
    pcap_set_immediate_mode(handle, 1);
    struct bpf_program fp; pcap_compile(handle, &fp, "tcp port 443", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    // retrieve MAC
    uint8_t mac[6];
    int fd = socket(AF_INET, SOCK_DGRAM, 0); struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1); ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); close(fd);

    map<Flow, Reassembly> flows;
    while (true) {
        pcap_pkthdr* hdr; const u_char* pkt;
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
        const uint8_t* data = pkt + sizeof(ether_header) + ip_len + tcp_len;

        Flow f{iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest)};
        auto& r = flows[f]; uint32_t seq = ntohl(tcph->seq);
        if (!r.in_progress) {
            if (dlen >= 5 && data[0] == 0x16) {
                uint16_t rec = (data[3] << 8) | data[4];
                r.base_seq = seq; r.expected = 5 + rec; r.in_progress = true;
                r.buf.insert(r.buf.end(), data, data + dlen);
            }
        } else {
            if (seq == r.base_seq + r.buf.size()) {
                r.buf.insert(r.buf.end(), data, data + dlen);
                if (r.buf.size() >= r.expected) {
                    string sni = parse_sni(r.buf.data(), r.buf.size());
                    r.buf.clear(); r.in_progress = false;
                    if (!sni.empty() && sni.find(pattern) != string::npos) {
                        // forward
                        inject_forward_rst(handle, pkt, iph, tcph, r.expected, mac);
                        // backward
                        iphdr rip = *iph; tcphdr rtc = *tcph;
                        rip.saddr = iph->daddr; rip.daddr = iph->saddr;
                        rtc.source = tcph->dest; rtc.dest = tcph->source;
                        rtc.seq = tcph->ack_seq;
                        rtc.ack_seq = htonl(ntohl(tcph->seq) + r.expected);
                        inject_backward_rst(&rip, &rtc, r.expected);
                        cout << "[+] TLS-blocked " << sni << endl;
                    }
                }
            } else flows.erase(f);
        }
    }
    pcap_close(handle);
    return 0;
}
