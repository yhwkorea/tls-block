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
    return (u16)(~sum);
}

// Inject RST|ACK to server (L2 via pcap_sendpacket)
void inject_rst_to_server(pcap_t* handle, const u_char* orig,
                          const struct iphdr* ip_hdr, const struct tcphdr* tcp_hdr,
                          int data_len, const uint8_t mac[6]) {
    int eth_sz = sizeof(struct ether_header);
    int ip_sz  = ip_hdr->ihl * 4;
    int tcp_sz = tcp_hdr->th_off * 4;
    int tot_sz = eth_sz + ip_sz + tcp_sz;
    static u_char out[1500];
    // Copy entire Ethernet + IP + TCP header
    memcpy(out, orig, tot_sz);
    // Overwrite source MAC
    struct ether_header* eh = (struct ether_header*)out;
    memcpy(eh->ether_shost, mac, 6);
    // IP header
    struct iphdr* iph = (struct iphdr*)(out + eth_sz);
    iph->tot_len = htons(ip_sz + tcp_sz);
    iph->check   = 0;
    iph->check   = checksum((u16*)iph, ip_sz);
    // TCP header
    struct tcphdr* tcph = (struct tcphdr*)(out + eth_sz + ip_sz);
    tcph->th_seq   = htonl(ntohl(tcp_hdr->th_seq) + data_len);
    tcph->th_ack   = tcp_hdr->th_ack; // preserve original ACK
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_off   = tcp_hdr->th_off;
    tcph->th_sum   = 0;
    // Pseudo-header checksum
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
    static u_char buf[1500];
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, tcp_sz);
    tcph->th_sum = checksum((u16*)buf, sizeof(pseudo) + tcp_sz);
    // Send L2 packet
    pcap_sendpacket(handle, out, tot_sz);
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
    tcph->seq     = tcp_hdr->th_ack;
    tcph->ack_seq = htonl(ntohl(tcp_hdr->th_seq) + data_len);
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_off   = tcp_hdr->th_off;
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
    pseudo.len   = htons(tcp_sz);
    vector<uint8_t> buf(sizeof(pseudo) + tcp_sz);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), tcph, tcp_sz);
    tcph->th_sum = checksum((u16*)buf.data(), buf.size());
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = iph->daddr;
    sendto(sd, pkt.data(), pkt_sz, 0, (struct sockaddr*)&dst, sizeof(dst));
    close(sd);
}

string parse_sni(const uint8_t* data, size_t len) {
    if (len < 5 || data[0] != 0x16) return "";
    uint16_t rec_len = ntohs(*(u16*)(data+3));
    inject_rst_to_server(handle, p, iph, tcph, r.expected, mac)
    size_t pos = 5;
    if (data[pos] != 0x01) return "";
    pos += 1 + 3; // msg type + length
    if (pos + 2 + 32 > len) return "";
    pos += 2 + 32;
    uint8_t sid_len = data[pos++]; pos += sid_len;
    uint16_t cs_len = (data[pos]<<8)|data[pos+1]; pos += 2 + cs_len;
    uint8_t comp_len = data[pos++]; pos += comp_len;
    uint16_t ext_total = (data[pos]<<8)|data[pos+1]; pos += 2;
    size_t end_ext = pos + ext_total;
    while (pos + 4 <= end_ext) {
        uint16_t type = (data[pos]<<8)|data[pos+1];
        uint16_t elen = (data[pos+2]<<8)|data[pos+3]; pos += 4;
        if (type == 0 && pos + elen <= end_ext) {
            pos += 2; pos += 1;
            uint16_t name_len = (data[pos]<<8)|data[pos+1]; pos += 2;
            return string((char*)(data + pos), name_len);
        }
        pos += elen;
    }
    return "";
}

struct Flow { in_addr src,dst; uint16_t sport,dport;
    bool operator<(const Flow& o) const {
        if (src.s_addr!=o.src.s_addr) return src.s_addr<o.src.s_addr;
        if (dst.s_addr!=o.dst.s_addr) return dst.s_addr<o.dst.s_addr;
        if (sport!=o.sport) return sport<o.sport;
        return dport<o.dport;
    }
};
struct Reassembly { uint32_t base_seq{}; vector<uint8_t> buf; size_t expected{}; bool got{}; };

int main(int argc,char*argv[]){
    if(argc!=3){cerr<<"syntax: tls-block <interface> <pattern>\n";return -1;}
    char* dev=argv[1]; string pat=argv[2];
    char err[PCAP_ERRBUF_SIZE];
    pcap_t*handle=pcap_open_live(dev,65535,1,-1,err);
    if(!handle){cerr<<err;return-1;} pcap_set_immediate_mode(handle,1);
    struct bpf_program fp; pcap_compile(handle,&fp,"tcp port 443",1,PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle,&fp);
    map<Flow,Reassembly> flows;
    while(true){
        pcap_pkthdr*h; const u_char*p;
        if(pcap_next_ex(handle,&h,&p)<=0) continue;
        ether_header*eh=(ether_header*)p; if(ntohs(eh->ether_type)!=ETH_P_IP) continue;
        iphdr*iph=(iphdr*)(p+sizeof(ether_header)); if(iph->protocol!=IPPROTO_TCP) continue;
        int ip_len=iph->ihl*4; tcphdr*tcph=(tcphdr*)(p+sizeof(ether_header)+ip_len);
        int tcp_len=tcph->th_off*4;
        int dlen=ntohs(iph->tot_len)-ip_len-tcp_len; if(dlen<=0) continue;
        const uint8_t*data=p+sizeof(ether_header)+ip_len+tcp_len;
        Flow f{iph->saddr,iph->daddr,ntohs(tcph->source),ntohs(tcph->dest)};
        auto& r=flows[f]; uint32_t seq=ntohl(tcph->seq);
        if(!r.got){ if(dlen>=5&&data[0]==0x16){ uint16_t rec=(data[3]<<8)|data[4]; r.base_seq=seq; r.expected=5+rec; r.got=true; r.buf.insert(r.buf.end(),data,data+dlen);} }
        else{ if(seq==r.base_seq+r.buf.size()){ r.buf.insert(r.buf.end(),data,data+dlen); if(r.buf.size()>=r.expected){ string sni=parse_sni(r.buf.data(),r.buf.size()); r.buf.clear(); r.got=false; if(!sni.empty() && sni.find(pat)!=string::npos){ // find MAC
                        ether_header* reth = (ether_header*)p; uint8_t mac[6]; memcpy(mac, reth->ether_shost, 6);
                        inject_rst_to_server(handle, pkt, iph, tcph, r.expected, mac); // send both sides
                        iphdr rip=*iph; tcphdr rtc=*tcph;
                        rip.saddr=iph->daddr; rip.daddr=iph->saddr;
                        rtc.source=tcph->dest; rtc.dest=tcph->source;
                        rtc.seq=tcph->ack_seq; rtc.ack_seq=htonl(ntohl(tcph->seq)+r.expected);
                        inject_rst_to_client(&rip, &rtc, r.expected);
                        cout<<"[+] TLS-blocked "<<sni<<"\n"; } } } else flows.erase(f);} }
    pcap_close(handle);
    return 0;
}
