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

// send raw packet bound to specific interface
void send_packet(const char* packet, int size, const in_addr& dst_ip, const char* dev) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return; }
    // bind to device
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

// inject RST|ACK using proper seq/ack and interface binding
void send_rst(const iphdr* ip_hdr, const tcphdr* tcp_hdr, int data_len, const char* dev) {
    int ip_len  = sizeof(iphdr);
    int tcp_len = tcp_hdr->th_off * 4;
    vector<uint8_t> pkt(ip_len + tcp_len);

    memcpy(pkt.data(), ip_hdr, ip_len);
    memcpy(pkt.data() + ip_len, tcp_hdr, tcp_len);

    // recalc IP checksum
    iphdr* iph = (iphdr*)pkt.data();
    iph->tot_len = htons(ip_len + tcp_len);
    iph->check   = 0;
    iph->check   = checksum((u16*)iph, ip_len);

    // set RST sequence/ack
    tcphdr* tcph = (tcphdr*)(pkt.data() + ip_len);
    uint32_t orig_seq = ntohl(tcp_hdr->th_seq);
    // use original ACK as RST seq
    tcph->th_seq   = tcp_hdr->th_ack;
    // keep original ack field (no change)
    tcph->th_ack   = tcp_hdr->th_ack;
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_off   = tcp_len / 4;
    tcph->th_sum   = 0;

    // pseudo-header for checksum
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

    in_addr dst_ip{ .s_addr = iph->daddr };
    send_packet((char*)pkt.data(), pkt.size(), dst_ip, dev);
}

// ... 나머지 parse_sni(), 재조립 로직, main() 은 그대로 ...
