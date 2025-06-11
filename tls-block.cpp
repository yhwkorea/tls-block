#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <map>
#include <string>

using namespace std;

// 16-bit checksum helper
typedef unsigned short u16;
u16 checksum(u16* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)(~sum);
}

// Send raw packet bound to specific interface
typedef struct iphdr iphdr;
void send_packet(const char* packet, int size, const in_addr& dst_ip, const char* dev) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return; }
        int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr = dst_ip;
    sendto(sock, packet, size, 0, (sockaddr*)&dst, sizeof(dst));
    close(sock);
}

// Inject RST|ACK (proper SEQ/ACK and full TCP header copy)
void send_rst(const iphdr* ip_hdr, const tcphdr* tcp_hdr, int data_len, const char* dev) {
    char buf[1500] = {};
    int ip_len = sizeof(iphdr);
    int tcp_len = tcp_hdr->th_off * 4;

    // Copy IP header
    iphdr* iph = (iphdr*)buf;
    memcpy(iph, ip_hdr, ip_len);
    iph->tot_len = htons(ip_len + tcp_len);
    iph->check = 0;
    iph->check = checksum((u16*)iph, ip_len);

    // Copy TCP header + options
    tcphdr* tcph = (tcphdr*)(buf + ip_len);
    memcpy(tcph, tcp_hdr, tcp_len);
    uint32_t orig_seq = ntohl(tcp_hdr->th_seq);
    uint32_t orig_ack = ntohl(tcp_hdr->th_ack);
    // Set RST sequence/ack according to RFC 793
    tcph->th_seq   = htonl(orig_ack);
    tcph->th_ack   = htonl(orig_seq + data_len);
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_off   = tcp_len / 4;
    tcph->th_sum   = 0;

    // Build pseudo-header for checksum
    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo;
    pseudo.src   = iph->saddr;
    pseudo.dst   = iph->daddr;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len   = htons(tcp_len);

    char tmp[1500] = {};
    memcpy(tmp, &pseudo, sizeof(pseudo));
    memcpy(tmp + sizeof(pseudo), tcph, tcp_len);
    tcph->th_sum = checksum((u16*)tmp, sizeof(pseudo) + tcp_len);

    // Send packet bound to interface
    in_addr dst_ip{};
    dst_ip.s_addr = iph->daddr;
    send_packet(buf, ip_len + tcp_len, dst_ip, dev);
}

// Extract SNI from TLS ClientHello
string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (len < 5 + rec_len) return "";
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
        uint16_t t = (data[pos] << 8) | data[pos+1];
        uint16_t l = (data[pos+2] << 8) | data[pos+3]; pos += 4;
        if (t == 0 && pos + l <= end_ext) {
            pos += 2; pos += 1;
            uint16_t name_len = (data[pos] << 8) | data[pos+1]; pos += 2;
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
struct Reassembly { uint32_t base_seq{}; vector<uint8_t> buf; size_t expected{}; bool got_len{}; };

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "syntax: tls-block <interface> <pattern>\n";
        return -1;
    }
    char* dev = argv[1];
    string pattern = argv[2];

    char err[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, -1, err);
    if (!handle) { cerr << err << endl; return -1; }
    pcap_set_immediate_mode(handle, 1);

    map<Flow, Reassembly> flows;
    while (true) {
        struct pcap_pkthdr* hdr;
        const u_char* pkt;
        if (pcap_next_ex(handle, &hdr, &pkt) <= 0) continue;
        iphdr* iph = (iphdr*)(pkt + 14);
        if (iph->protocol != IPPROTO_TCP) continue;
        int ip_len = iph->ihl * 4;
        tcphdr* tcph = (tcphdr*)(pkt + 14 + ip_len);
        int tcp_len = tcph->th_off * 4;
        int dlen = ntohs(iph->tot_len) - ip_len - tcp_len;
        if (dlen <= 0) continue;
        const uint8_t* data = pkt + 14 + ip_len + tcp_len;

        Flow f{iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest)};
        auto& r = flows[f];
        uint32_t seq = ntohl(tcph->seq);

        if (r.buf.empty()) {
            string sni = parse_sni(data, dlen);
            if (!sni.empty() && sni.find(pattern) != string::npos) {
                send_rst(iph, tcph, dlen, dev);
                iphdr rev_iph = *iph;
                tcphdr rev_tcph = *tcph;
                rev_iph.saddr = iph->daddr;
                rev_iph.daddr = iph->saddr;
                rev_tcph.source = tcph->dest;
                rev_tcph.dest = tcph->source;
                rev_tcph.seq = tcph->ack_seq;
                rev_tcph.ack_seq = htonl(ntohl(tcph->seq) + dlen);
                send_rst(&rev_iph, &rev_tcph, dlen, dev);
                cout << "[+] TLS-blocked " << sni << endl;
            } else if (dlen >= 5 && data[0] == 0x16) {
                uint16_t rec = (data[3] << 8) | data[4];
                r.base_seq = seq;
                r.expected = 5 + rec;
                r.got_len = true;
                r.buf.insert(r.buf.end(), data, data + dlen);
            }
        } else {
            if (seq == r.base_seq + r.buf.size()) {
                r.buf.insert(r.buf.end(), data, data + dlen);
                if (!r.got_len && r.buf.size() >= 5) {
                    uint16_t rec = (r.buf[3] << 8) | r.buf[4];
                    r.expected = 5 + rec;
                    r.got_len = true;
                }
                if (r.got_len && r.buf.size() >= r.expected) {
                    string sni = parse_sni(r.buf.data(), r.buf.size());
                    flows.erase(f);
                    if (sni.find(pattern) != string::npos) {
                        send_rst(iph, tcph, dlen, dev);
                        iphdr rev_iph = *iph;
                        tcphdr rev_tcph = *tcph;
                        rev_iph.saddr = iph->daddr;
                        rev_iph.daddr = iph->saddr;
                        rev_tcph.source = tcph->dest;
                        rev_tcph.dest = tcph->source;
                        rev_tcph.seq = tcph->ack_seq;
                        rev_tcph.ack_seq = htonl(ntohl(tcph->seq) + dlen);
                        send_rst(&rev_iph, &rev_tcph, dlen, dev);
                        cout << "[+] TLS-blocked " << sni << endl;
                    }
                }
            } else {
                flows.erase(f);
            }
        }
    }
    pcap_close(handle);
    return 0;
}
