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

typedef unsigned short u16;
u16 checksum(u16* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)(~sum);
}

void send_packet(const char* packet, int size, const struct in_addr& dst_ip, const char* dev) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return; }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr = dst_ip;
    sendto(sock, packet, size, 0, (struct sockaddr*)&dst, sizeof(dst));
    close(sock);
}

void send_rst(const struct iphdr* ip_hdr, const struct tcphdr* tcp_hdr, int data_len, const char* dev) {
    int ip_len = sizeof(struct iphdr);
    int tcp_len = tcp_hdr->th_off * 4;
    vector<uint8_t> pkt(ip_len + tcp_len);
    memcpy(pkt.data(), ip_hdr, ip_len);
    memcpy(pkt.data() + ip_len, tcp_hdr, tcp_len);

    struct iphdr* iph = (struct iphdr*)pkt.data();
    iph->tot_len = htons(ip_len + tcp_len);
    iph->check = 0;
    iph->check = checksum((u16*)iph, ip_len);

    struct tcphdr* tcph = (struct tcphdr*)(pkt.data() + ip_len);
    uint32_t orig_seq = ntohl(tcp_hdr->th_seq);
    uint32_t orig_ack = ntohl(tcp_hdr->th_ack);
    tcph->th_seq   = htonl(orig_ack);
    tcph->th_ack   = htonl(orig_seq + data_len);
    tcph->th_flags = TH_RST;
    tcph->th_off   = tcp_len / 4;
    tcph->th_sum   = 0;

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

    vector<uint8_t> buf(sizeof(pseudo) + tcp_len);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), tcph, tcp_len);
    tcph->th_sum = checksum((u16*)buf.data(), buf.size());

    struct in_addr dst_ip{};
    dst_ip.s_addr = iph->daddr;
    send_packet((const char*)pkt.data(), pkt.size(), dst_ip, dev);
}

string parse_sni(const uint8_t* data, size_t len) { /* unchanged */
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (len < 5 + rec_len) return "";
    size_t pos = 5;
    if (pos + 4 > len || data[pos] != 0x01) return "";
    uint32_t hs_len = (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
    pos += 4; if (pos + hs_len > len) return "";
    pos += 2 + 32;
    uint8_t sid = data[pos++]; pos += sid;
    uint16_t cs = (data[pos] << 8) | data[pos+1]; pos += 2 + cs;
    uint8_t cl = data[pos++]; pos += cl;
    uint16_t ext_total = (data[pos] << 8) | data[pos+1]; pos += 2;
    size_t end_ext = pos + ext_total;
    while (pos + 4 <= end_ext) {
        uint16_t t = (data[pos] << 8) | data[pos+1];
        uint16_t l = (data[pos+2] << 8) | data[pos+3]; pos += 4;
        if (t == 0 && pos + l <= end_ext) {
            pos += 2; pos += 1;
            uint16_t nl = (data[pos] << 8) | data[pos+1]; pos += 2;
            return string((char*)(data + pos), nl);
        }
        pos += l;
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
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65535, 1, -1, err);
    if (!handle) { cerr << err << endl; return -1; }
    pcap_set_immediate_mode(handle, 1);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 443", 1, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);

    map<Flow, Reassembly> flows;
    while (true) {
        struct pcap_pkthdr* hdr; const u_char* pkt;
        if (pcap_next_ex(handle, &hdr, &pkt) <= 0) continue;
        struct iphdr* iph = (struct iphdr*)(pkt + 14);
        if (iph->protocol != IPPROTO_TCP) continue;
        int ip_len = iph->ihl * 4;
        struct tcphdr* tcph = (struct tcphdr*)(pkt + 14 + ip_len);
        int tcp_len = tcph->th_off * 4;
        int dlen = ntohs(iph->tot_len) - ip_len - tcp_len;
        if (dlen <= 0) continue;
        const uint8_t* data = pkt + 14 + ip_len + tcp_len;

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
                        send_rst(iph, tcph, r.expected, dev);
                        struct iphdr rev_iph = *iph;
                        struct tcphdr rev_tcph = *tcph;
                        rev_iph.saddr = iph->daddr;
                        rev_iph.daddr = iph->saddr;
                        rev_tcph.source = tcph->dest;
                        rev_tcph.dest = tcph->source;
                        rev_tcph.seq = tcph->ack_seq;
                        rev_tcph.ack_seq = htonl(ntohl(tcph->seq) + r.expected);
                        send_rst(&rev_iph, &rev_tcph, r.expected, dev);
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
