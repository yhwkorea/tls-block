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

// Simple 5-byte IP checksum
uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// Raw send using IP_HDRINCL
void send_packet(const char* packet, int size, const in_addr& dst_ip) {
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

// Send a single RST packet (with ACK) for the given headers
void send_rst(const ip* ip_hdr, const tcphdr* tcp_hdr) {
    char buffer[1500] = {};
    ip* iph = (ip*)buffer;
    tcphdr* tcph = (tcphdr*)(buffer + sizeof(ip));

    // Copy and swap headers
    *iph = *ip_hdr;
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr));
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t*)iph, sizeof(ip));

    *tcph = *tcp_hdr;
    // Sequence and ack: reset sequence next
    tcph->th_seq = htonl(ntohl(tcp_hdr->th_seq) + 1);
    tcph->th_ack = htonl(ntohl(tcp_hdr->th_ack));
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_off = sizeof(tcphdr) / 4;
    tcph->th_sum = 0;

    // Pseudo-header for checksum
    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo;
    pseudo.src = iph->ip_src.s_addr;
    pseudo.dst = iph->ip_dst.s_addr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(sizeof(tcphdr));

    char tmp[1500] = {};
    memcpy(tmp, &pseudo, sizeof(pseudo));
    memcpy(tmp + sizeof(pseudo), tcph, sizeof(tcphdr));
    tcph->th_sum = checksum((uint16_t*)tmp, sizeof(pseudo) + sizeof(tcphdr));

    send_packet(buffer, sizeof(ip) + sizeof(tcphdr), iph->ip_dst);
}

// Parse SNI from a complete TLS ClientHello record
string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return ""; // Not a handshake
    uint16_t rec_len = (data[3] << 8) | data[4];
    if (len < 5 + rec_len) return "";
    size_t pos = 5;
    if (pos + 4 > len) return "";
    if (data[pos] != 0x01) return ""; // Not ClientHello
    uint32_t hs_len = ((data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3]);
    pos += 4;
    if (pos + hs_len > len) return "";
    // Skip: version(2), random(32)
    pos += 2 + 32;
    // Session ID
    if (pos + 1 > len) return "";
    uint8_t sid_len = data[pos++];
    pos += sid_len;
    // Cipher suites
    if (pos + 2 > len) return "";
    uint16_t cs_len = (data[pos] << 8) | data[pos+1];
    pos += 2 + cs_len;
    // Compression methods
    if (pos + 1 > len) return "";
    uint8_t comp_len = data[pos++];
    pos += comp_len;
    // Extensions
    if (pos + 2 > len) return "";
    uint16_t ext_total = (data[pos] << 8) | data[pos+1];
    pos += 2;
    size_t end_ext = pos + ext_total;
    while (pos + 4 <= end_ext) {
        uint16_t ext_type = (data[pos] << 8) | data[pos+1];
        uint16_t ext_len  = (data[pos+2] << 8) | data[pos+3];
        pos += 4;
        if (ext_type == 0x0000 && pos + ext_len <= end_ext) {
            // SNI list
            uint16_t list_len = (data[pos] << 8) | data[pos+1];
            pos += 2;
            if (pos + list_len <= end_ext) {
                uint8_t name_type = data[pos];
                uint16_t name_len = (data[pos+1] << 8) | data[pos+2];
                pos += 3;
                if (pos + name_len <= end_ext)
                    return string((const char*)data + pos, name_len);
            }
            break;
        }
        pos += ext_len;
    }
    return "";
}

// Flow key for reassembly
struct Flow {
    in_addr src; in_addr dst;
    uint16_t sport, dport;
    bool operator<(Flow const& o) const {
        if (src.s_addr != o.src.s_addr) return src.s_addr < o.src.s_addr;
        if (dst.s_addr != o.dst.s_addr) return dst.s_addr < o.dst.s_addr;
        if (sport != o.sport) return sport < o.sport;
        return dport < o.dport;
    }
};

struct Reassembly {
    uint32_t base_seq{};
    vector<uint8_t> buf;
    size_t expected{};
    bool got_length{};
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "syntax: tls-block <interface> <servername>\n";
        return -1;
    }
    char* dev = argv[1];
    string target_sni = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) { cerr << errbuf; return -1; }
    map<Flow, Reassembly> flows;

    while (true) {
        struct pcap_pkthdr* hdr;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res <= 0) continue;
        const ip* iph = (ip*)(pkt + 14);
        if (iph->ip_p != IPPROTO_TCP) continue;
        int ip_len = iph->ip_hl * 4;
        const tcphdr* tcph = (tcphdr*)(pkt + 14 + ip_len);
        int tcp_len = tcph->th_off * 4;
        int data_len = ntohs(iph->ip_len) - ip_len - tcp_len;
        if (data_len <= 0) continue;
        const uint8_t* data = pkt + 14 + ip_len + tcp_len;

        Flow f{iph->ip_src, iph->ip_dst, ntohs(tcph->th_sport), ntohs(tcph->th_dport)};
        auto& r = flows[f];
        uint32_t seq = ntohl(tcph->th_seq);

        // Reassembly logic
        if (r.buf.empty()) {
            // Starting new flow
            string sni = parse_sni(data, data_len);
            if (!sni.empty()) {
                if (sni == target_sni) {
                    // Block immediately
                    send_rst(iph, tcph);
                    // reverse direction
                    ip iph_rev = *iph;
                    tcphdr tcph_rev = *tcph;
                    iph_rev.ip_src = iph->ip_dst;
                    iph_rev.ip_dst = iph->ip_src;
                    tcph_rev.th_sport = tcph->th_dport;
                    tcph_rev.th_dport = tcph->th_sport;
                    tcph_rev.th_seq = tcph->th_ack;
                    tcph_rev.th_ack = htonl(ntohl(tcph->th_seq) + data_len);
                    send_rst(&iph_rev, &tcph_rev);
                    cout << "[+] TLS-blocked " << sni << "\n";
                }
            } else if (data_len >= 5 && data[0] == 0x16) {
                // incomplete: start buffer
                uint16_t rec_len = (data[3]<<8)|data[4];
                r.base_seq = seq;
                r.expected = 5 + rec_len;
                r.got_length = true;
                r.buf.insert(r.buf.end(), data, data + data_len);
            }
        } else {
            // continue reassembly
            if (seq == r.base_seq + r.buf.size()) {
                r.buf.insert(r.buf.end(), data, data + data_len);
                if (!r.got_length && r.buf.size() >= 5) {
                    uint16_t rec_len = (r.buf[3]<<8)|r.buf[4];
                    r.expected = 5 + rec_len;
                    r.got_length = true;
                }
                if (r.got_length && r.buf.size() >= r.expected) {
                    string sni = parse_sni(r.buf.data(), r.buf.size());
                    flows.erase(f);
                    if (sni == target_sni) {
                        send_rst(iph, tcph);
                        ip iph_rev = *iph;
                        tcphdr tcph_rev = *tcph;
                        iph_rev.ip_src = iph->ip_dst;
                        iph_rev.ip_dst = iph->ip_src;
                        tcph_rev.th_sport = tcph->th_dport;
                        tcph_rev.th_dport = tcph->th_sport;
                        tcph_rev.th_seq = tcph->th_ack;
                        tcph_rev.th_ack = htonl(ntohl(tcph->th_seq) + data_len);
                        send_rst(&iph_rev, &tcph_rev);
                        cout << "[+] TLS-blocked " << sni << "\n";
                    }
                }
            } else {
                // out-of-order: drop buffer
                flows.erase(f);
            }
        }
    }
    pcap_close(handle);
    return 0;
}
