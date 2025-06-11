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
    cout << "syntax : tls-block <interface> <server_name>\n";
    cout << "sample  : tls-block wlan0 naver.com\n";
}

static u16 checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (u16)(~sum);
}

// Parse SNI from single-record TLS ClientHello
static string parse_sni(const uint8_t* payload_data, size_t payload_len) {
    if (payload_len < 5 || payload_data[0] != 0x16) return "";
    uint16_t record_len = (payload_data[3] << 8) | payload_data[4];
    if (payload_len < (size_t)5 + record_len) return "";
    size_t offset = 5;
    if (offset + 4 > payload_len || payload_data[offset] != 0x01) return "";
    uint32_t hs_len = (payload_data[offset+1]<<16)
                    | (payload_data[offset+2]<<8)
                    |  payload_data[offset+3];
    offset += 4;
    if (offset + hs_len > payload_len) return "";
    offset += 2 + 32;  // version + random
    if (offset >= payload_len) return "";
    uint8_t sid_len = payload_data[offset++];
    offset += sid_len;
    if (offset + 2 > payload_len) return "";
    uint16_t cs_len = (payload_data[offset]<<8)|payload_data[offset+1];
    offset += 2 + cs_len;
    if (offset >= payload_len) return "";
    uint8_t comp_len = payload_data[offset++];
    offset += comp_len;
    if (offset + 2 > payload_len) return "";
    uint16_t ext_total = (payload_data[offset]<<8)|payload_data[offset+1];
    offset += 2;
    size_t end_of_ext = offset + ext_total;
    // https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FI5TLu%2FbtrBRoSgSI2%2FVRgHO2rNOljLsP9IsAYwaK%2Fimg.jpg
    while (offset + 4 <= end_of_ext && offset + 4 <= payload_len) {
        uint16_t ext_type = (payload_data[offset]<<8)|payload_data[offset+1];
        uint16_t ext_len  = (payload_data[offset+2]<<8)|payload_data[offset+3];
        offset += 4;
        if (ext_type == 0x0000 && offset + ext_len <= end_of_ext) {
            offset += 3; // skip list length + name type
            uint16_t name_len = (payload_data[offset]<<8)|payload_data[offset+1];
            offset += 2;
            if (offset + name_len <= end_of_ext) {
                return string((char*)(payload_data + offset), name_len);
            } else {
                return "";
            }
        }
        offset += ext_len;
    }
    return "";
}

struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator==(const FlowKey& o) const {
        return src_ip==o.src_ip && dst_ip==o.dst_ip
            && src_port==o.src_port && dst_port==o.dst_port;
    }
};

struct FlowKeyHash {
    size_t operator()(FlowKey const& k) const noexcept {
        return k.src_ip ^ (k.dst_ip<<1)
             ^ ((size_t)k.src_port<<16) ^ ((size_t)k.dst_port<<1);
    }
};

struct Reassembly {
    uint32_t base_seq{};
    size_t   expected_len{};
    vector<uint8_t> buffer;
    bool     in_progress{};
};

// 고정 크기 전송 버퍼
static u_char send_buffer[1500];

// 서버 방향 RST+ACK 주입 (pcap)
static void send_rst_to_server(pcap_t* pc,
    const u_char* orig_packet,
    const iphdr* ip_hdr_orig,
    const tcphdr* tcp_hdr_orig,
    int payload_len,
    const uint8_t mac_addr[6])
{
    int ether_header_size = sizeof(ether_header);
    int ip_header_len     = ip_hdr_orig->ihl * 4;
    int tcp_header_len    = tcp_hdr_orig->th_off * 4;
    int packet_size       = ether_header_size + ip_header_len + tcp_header_len;

    memcpy(send_buffer, orig_packet, packet_size);
    auto* eth = (ether_header*)send_buffer;
    memcpy(eth->ether_shost, mac_addr, 6);

    auto* new_ip = (iphdr*)(send_buffer + ether_header_size);
    new_ip->tot_len = htons(ip_header_len + tcp_header_len);
    new_ip->check   = 0;
    new_ip->check   = checksum((u16*)new_ip, ip_header_len);

    auto* new_tcp = (tcphdr*)(send_buffer + ether_header_size + ip_header_len);
    new_tcp->seq     = htonl(ntohl(tcp_hdr_orig->seq) + payload_len);
    new_tcp->ack_seq = tcp_hdr_orig->ack_seq;
    new_tcp->rst     = 1;
    new_tcp->ack     = 1;
    new_tcp->th_off  = tcp_header_len / 4;
    new_tcp->check   = 0;

    struct {
        uint32_t src, dst;
        uint8_t  zero, proto;
        uint16_t len;
    } pseudo_hdr = {
        new_ip->saddr,
        new_ip->daddr,
        0,
        IPPROTO_TCP,
        htons(tcp_header_len)
    };

    vector<u_char> chk_buf(sizeof(pseudo_hdr) + tcp_header_len);
    memcpy(chk_buf.data(), &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(chk_buf.data() + sizeof(pseudo_hdr), new_tcp, tcp_header_len);
    new_tcp->check = checksum((u16*)chk_buf.data(), chk_buf.size());

    pcap_sendpacket(pc, send_buffer, packet_size);
}

// 클라이언트 방향 RST+ACK 주입 (raw socket)
static void send_rst_to_client(const iphdr* ip_hdr_orig,
    const tcphdr* tcp_hdr_orig,
    int payload_len)
{
    int ip_header_len  = ip_hdr_orig->ihl * 4;
    int tcp_header_len = tcp_hdr_orig->th_off * 4;
    int packet_size    = ip_header_len + tcp_header_len;

    vector<u_char> pkt(packet_size);
    memcpy(pkt.data(), ip_hdr_orig,  ip_header_len);
    memcpy(pkt.data()+ip_header_len, tcp_hdr_orig, tcp_header_len);

    auto* new_ip = (iphdr*)pkt.data();
    new_ip->saddr   = ip_hdr_orig->daddr;
    new_ip->daddr   = ip_hdr_orig->saddr;
    new_ip->tot_len = htons(packet_size);
    new_ip->check   = 0;
    new_ip->check   = checksum((u16*)new_ip, ip_header_len);

    auto* new_tcp = (tcphdr*)(pkt.data() + ip_header_len);
    new_tcp->source   = tcp_hdr_orig->dest;
    new_tcp->dest     = tcp_hdr_orig->source;
    new_tcp->seq      = tcp_hdr_orig->ack_seq;
    new_tcp->ack_seq  = htonl(ntohl(tcp_hdr_orig->seq) + payload_len);
    new_tcp->rst      = 1;
    new_tcp->ack      = 1;
    new_tcp->th_off   = tcp_header_len / 4;
    new_tcp->check    = 0;

    struct {
        uint32_t src, dst;
        uint8_t  zero, proto;
        uint16_t len;
    } pseudo_hdr = {
        new_ip->saddr,
        new_ip->daddr,
        0,
        IPPROTO_TCP,
        htons(tcp_header_len)
    };

    vector<u_char> chk_buf(sizeof(pseudo_hdr) + tcp_header_len);
    memcpy(chk_buf.data(), &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(chk_buf.data() + sizeof(pseudo_hdr), new_tcp, tcp_header_len);
    new_tcp->check = checksum((u16*)chk_buf.data(), chk_buf.size());

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int on = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    sockaddr_in dst_addr{};
    dst_addr.sin_family      = AF_INET;
    dst_addr.sin_addr.s_addr = new_ip->daddr;
    sendto(raw_sock, pkt.data(), packet_size, 0,
           (sockaddr*)&dst_addr, sizeof(dst_addr));
    close(raw_sock);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        usage();
        return 1;
    }
    char* interface = argv[1];
    string pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pc = pcap_open_live(interface, 65535, 1, 1, errbuf);
    if (!pc) {
        cerr << "Error opening " << interface << ": " << errbuf << "\n";
        return 1;
    }
    pcap_set_immediate_mode(pc, 1);

    // MAC 주소 조회
    uint8_t mac_addr[6];
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifreq iface_req{};
    strncpy(iface_req.ifr_name, interface, IFNAMSIZ-1);
    ioctl(sock_fd, SIOCGIFHWADDR, &iface_req);
    memcpy(mac_addr, iface_req.ifr_hwaddr.sa_data, 6);
    close(sock_fd);

    unordered_map<FlowKey, Reassembly, FlowKeyHash> flow_map;
    flow_map.reserve(1024);

    while (true) {
        pcap_pkthdr* header;
        const u_char* packet;
        if (pcap_next_ex(pc, &header, &packet) <= 0) continue;

        auto* eth_hdr = (ether_header*)packet;
        if (ntohs(eth_hdr->ether_type) != ETH_P_IP) continue;

        auto* ip_hdr = (iphdr*)(packet + sizeof(ether_header));
        if (ip_hdr->protocol != IPPROTO_TCP) continue;

        int ip_header_len = ip_hdr->ihl * 4;
        auto* tcp_hdr = (tcphdr*)(packet + sizeof(ether_header) + ip_header_len);
        int tcp_header_len = tcp_hdr->th_off * 4;
        int payload_len = ntohs(ip_hdr->tot_len) - ip_header_len - tcp_header_len;
        if (payload_len <= 0) continue;

        const uint8_t* payload_data = (uint8_t*)tcp_hdr + tcp_header_len;
        FlowKey conn_key{ip_hdr->saddr, ip_hdr->daddr,
                         ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest)};
        auto& reassembler = flow_map[conn_key];
        uint32_t seq_num = ntohl(tcp_hdr->seq);

        if (!reassembler.in_progress) {
            string host = parse_sni(payload_data, payload_len);
            if (!host.empty() && host.find(pattern) != string::npos) {
                send_rst_to_server(pc, packet, ip_hdr, tcp_hdr, payload_len, mac_addr);
                send_rst_to_client(ip_hdr, tcp_hdr, payload_len);
                cout << "[+] Blocked: " << host << "\n";
            }

        }
    }
    pcap_close(pc);
    return 0;
}
