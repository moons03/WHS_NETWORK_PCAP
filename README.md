```c
struct ethheader {
...
};

/* IP Header */
struct ipheader {
...
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};
```

 Ethernet, IP, TCP 헤더를 구현하는 구조체입니다. myheader.h에서 가져와서 구현했습니다. 

```c
int main()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
```

sniff_improved.c에서 가져와서 만들었습니다. 여기 코드에서는 pcap 세션을 열고 tcp 패킷만 필터링하도록 컴파일 한 후 패킷이 캡쳐되었을 때 got_packet을 콜백 합니다. 

```c
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    struct ethheader* eth = (struct ethheader*)packet;

    printf("       MAC src: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("       MAC dst: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));

        printf("------------------------------\n");
        printf("       IPv4 src: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("       IPv4 dst: %s\n", inet_ntoa(ip->iph_destip));
        
        if ((ip->iph_protocol) == IPPROTO_TCP) {
            int iph_length = ip->iph_ihl * 4;
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + iph_length);

            printf("------------------------------\n"); 
            printf("       TCP src port: %d\n", ntohs(tcp->tcp_sport));
            printf("       TCP dst port: %d\n", ntohs(tcp->tcp_dport));

            int tcp_offset = TH_OFF(tcp) * 4;
            int message_length = ntohs(ip->iph_len) - iph_length - tcp_offset;
            const u_char* message = packet + sizeof(struct ethheader) + iph_length + tcp_offset;
            
            if (message_length > 0) {
                printf("Message: ", message);
                 for (int i = 0; i < message_length; i++) {
                    if (i == 100) {
                        printf("...");
                        break;
                    }
                    printf("%c", message[i]);
                }
            }
            printf("\n");
        }
    }
}
```

MAC주소 출력은 콜백 함수의 인자인 packet을 사용해여 ethheader로 SRC MAC, DST MAC 주소를 추출 했습니다. IP 주소 출력은 packet을 ethheader 구조체크기 만큼 더한 후 ipheader 로 받아옵니다. 그리고 inet_ntoa 함수를 사용해서 IP 주소를 보기 쉬운 형태로 만들어준 다음에 출력 합니다. 포트는 tcp 헤더에 있기 때문에 packet에 ethheader 구조체 사이즈 + ip헤더 길이(ip헤더 실제의 길이는 ip헤서의 써있는 길이의 4배 이기에 * 4) 를 더한 것에 tcpheader 로 받아옵니다. 그다음 빅엔디안으로 저장 되어있는 port를 ntohs로 리틀엔디안으로 바꿔서 출력합니다. 마지막으로는 message 를 가져와보겠습니다. message의 내용을 가져오려먼 packet에 tcp헤더 위치까지 더하고 tcp offset만큼 더하면 됩니다. tcp offset은 TH_OFF를 사용해서 구할 수 있습니다. 여기서 추가로 message가 일정 길이만 출력되도록 하려면 message 길이를 알아야하는데 이것은 ip헤더의 ip패킷 전체길이를 받아오고 ip헤더 크기랑 tcp off를 빼면 message 길이를 얻을 수 있습니다.