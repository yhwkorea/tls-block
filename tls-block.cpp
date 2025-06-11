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

// Simple IP checksum calculation
typedef unsigned short u16;
u16 checksum(u16* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)(~sum);
}

// Send raw packet on specific interface
void send_packet(const char* packet, int size, const in_addr& dst_ip, const char* dev) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return; }
    // Bind to device
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) < 0) {
        perror("SO_BINDTODEVICE");
    }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr = dst_ip;
    sendto(sock, packet, size, 0, (sockaddr*)&dst, sizeof(dst));
    close(sock);
}

// Inject RST|ACK packet
void send_rst(const ip* ip_hdr, const tcphdr* tcp_hdr, int data_len, const char* dev) {
    char buf[1500] = {};
    ip* iph = (ip*)buf;
    tcphdr* tcph = (tcphdr*)(buf + sizeof(ip));

    *iph = *ip_hdr;
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr));
    iph->ip_sum = 0;
    iph->ip_sum = checksum((u16*)iph, sizeof(ip));

    *tcph = *tcp_hdr;
    // seq = original seq + payload length
    tcph->th_seq   = htonl(ntohl(tcp_hdr->th_seq) + data_len);
    // ack = original ack (no change)
    tcph->th_ack   = tcp_hdr->th_ack;
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_off   = sizeof(tcphdr)/4;
    tcph->th_sum   = 0;

    // pseudo-header for checksum
    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo;
    pseudo.src   = iph->ip_src.s_addr;
    pseudo.dst   = iph->ip_dst.s_addr;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len   = htons(sizeof(tcphdr));

    char tmp[1500] = {};
    memcpy(tmp, &pseudo, sizeof(pseudo));
    memcpy(tmp + sizeof(pseudo), tcph, sizeof(tcphdr));
    tcph->th_sum = checksum((u16*)tmp, sizeof(pseudo) + sizeof(tcphdr));

    send_packet(buf, sizeof(ip) + sizeof(tcphdr), iph->ip_dst, dev);
}

// Parse SNI from TLS ClientHello
string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = (data[3]<<8) | data[4];
    if (len < 5 + rec_len) return "";
    size_t pos = 5;
    if (pos+4 > len || data[pos] != 0x01) return "";
    uint32_t hs_len = (data[pos+1]<<16) | (data[pos+2]<<8) | data[pos+3];
    pos += 4;
    if (pos + hs_len > len) return "";
    pos += 2 + 32;
    uint8_t sid_len = data[pos++]; pos += sid_len;
    uint16_t cs_len = (data[pos]<<8) | data[pos+1]; pos += 2 + cs_len;
    uint8_t comp_len = data[pos++]; pos += comp_len;
    uint16_t ext_len = (data[pos]<<8) | data[pos+1]; pos += 2;
    size_t end_ext = pos + ext_len;
    while (pos + 4 <= end_ext) {
        uint16_t t = (data[pos]<<8) | data[pos+1];
        uint16_t l = (data[pos+2]<<8) | data[pos+3]; pos += 4;
        if (t == 0 && pos + l <= end_ext) {
            pos += 2; // list length
            pos += 1; // name_type
            uint16_t nl = (data[pos]<<8) | data[pos+1]; pos += 2;
            return string((char*)(data + pos), nl);
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
    if (argc != 3) { cerr << "syntax: tls-block <interface> <pattern>\n"; return -1; }
    char* dev = argv[1];
    string pat = argv[2];
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* h = pcap_open_live(dev, BUFSIZ, 1, -1, err);
    if (!h) { cerr << err; return -1; }
    pcap_set_immediate_mode(h, 1);

    map<Flow, Reassembly> flows;
    while (true) {
        pcap_pkthdr* hdr; const u_char* pkt;
        if (pcap_next_ex(h, &hdr, &pkt) <= 0) continue;
        ip* iph = (ip*)(pkt + 14);
        if (iph->ip_p != IPPROTO_TCP) continue;
        int ip_len = iph->ip_hl * 4;
        tcphdr* tcph = (tcphdr*)(pkt + 14 + ip_len);
        int tcp_len = tcph->th_off * 4;
        int dlen = ntohs(iph->ip_len) - ip_len - tcp_len;
        if (dlen <= 0) continue;
        const uint8_t* data = pkt + 14 + ip_len + tcp_len;

        Flow f{iph->ip_src, iph->ip_dst, ntohs(tcph->th_sport), ntohs(tcph->th_dport)};
        auto& r = flows[f];
        uint32_t seq = ntohl(tcph->th_seq);

        if (r.buf.empty()) {
            string sni = parse_sni(data, dlen);
            if (!sni.empty() && sni.find(pat) != string::npos) {
                send_rst(iph, tcph, dlen, dev);
                ip iph_rev = *iph;
                tcphdr tcph_rev = *tcph;
                iph_rev.ip_src = iph->ip_dst;
                iph_rev.ip_dst = iph->ip_src;
                tcph_rev.th_sport = tcph->th_dport;
                tcph_rev.th_dport = tcph->th_sport;
                tcph_rev.th_seq = tcph->th_ack;
                tcph_rev.th_ack = htonl(ntohl(tcph->th_seq) + dlen);
                send_rst(&iph_rev, &tcph_rev, dlen, dev);
                cout << "[+] TLS-blocked " << sni << "\n";
            } else if (dlen >= 5 && data[0] == 0x16) {
                uint16_t rec = (data[3]<<8) | data[4];
                r.base_seq = seq;
                r.expected = 5 + rec;
                r.got_len = true;
                r.buf.insert(r.buf.end(), data, data + dlen);
            }
        } else {
            if (seq == r.base_seq + r.buf.size()) {
                r.buf.insert(r.buf.end(), data, data + dlen);
                if (!r.got_len && r.buf.size() >= 5) {
                    uint16_t rec = (r.buf[3]<<8) | r.buf[4];
                    r.expected = 5 + rec;
                    r.got_len = true;
                }
                if (r.got_len && r.buf.size() >= r.expected) {
                    string sni = parse_sni(r.buf.data(), r.buf.size());
                    flows.erase(f);
                    if (sni.find(pat) != string::npos) {
                        send_rst(iph, tcph, dlen, dev);
                        ip iph_rev = *iph;
                        tcphdr tcph_rev = *tcph;
                        iph_rev.ip_src = iph->ip_dst;
                        iph_rev.ip_dst = iph->ip_src;
                        tcph_rev.th_sport = tcph->th_dport;
                        tcph_rev.th_dport = tcph->th_sport;
                        tcph_rev.th_seq = tcph->th_ack;
                        tcph_rev.th_ack = htonl(ntohl(tcph->th_seq) + dlen);
                        send_rst(&iph_rev, &tcph_rev, dlen, dev);
                        cout << "[+] TLS-blocked " << sni << "\n";
                    }
                }
            } else {
                flows.erase(f);
            }
        }
    }
    pcap_close(h);
    return 0;
}
