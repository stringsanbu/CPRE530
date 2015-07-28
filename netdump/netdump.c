#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char* user, const struct pcap_pkthdr* h, const u_char* p);

int packettype;

char* program_name;

/* Externs */
extern void bpf_dump(struct bpf_program*, int);
void print_icmp_packet(const u_char* Buffer , int Size);
extern char* copy_argv(char**);

/* Forwards */
void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;

static pcap_t* pd;

extern int optind;
extern int opterr;
extern char* optarg;
int pflag = 0, aflag = 0;
int cnt_broadcast = 0;
int cnt_arp = 0;
int cnt_ip = 0;
int cnt_icmp = 0;
/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1 /* ARP Request             */
#define ARP_REPLY 2   /* ARP Reply               */
typedef struct arphdr {
    u_int16_t htype; /* Hardware Type           */
    u_int16_t ptype; /* Protocol Type           */
    u_char hlen;     /* Hardware Address Length */
    u_char plen;     /* Protocol Address Length */
    u_int16_t oper;  /* Operation Code          */
    u_char sha[6];   /* Sender hardware address */
    u_char spa[4];   /* Sender IP address       */
    u_char tha[6];   /* Target hardware address */
    u_char tpa[4];   /* Target IP address       */
} arphdr_t;

struct iphdr {
	u_int8_t	ihl:4;
	u_int8_t	version:4;
	u_int8_t	tos;
	u_int16_t	tot_len;
	u_int16_t	id;
	u_int16_t	frag_off;
	u_int8_t	ttl;
	u_int8_t	protocol;
	u_int16_t	check;
	u_int32_t	saddr;
	u_int32_t	daddr;

};

struct icmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
      u_int16_t	id;
      u_int16_t	sequence;
};
struct tcphdr {
         u_int16_t   source;
         u_int16_t   dest;
         u_int32_t   seq;
         u_int32_t   ack_seq;
         u_int16_t   res1:4,
                 doff:4,
                 fin:1,
                 syn:1,
                 rst:1,
                 psh:1,
                 ack:1,
                 urg:1,
                 ece:1,
                 cwr:1;
		 u_int16_t   window;
         u_int16_t   check;
         u_int16_t   urg_ptr;

};
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void print_payload(const u_char *payload, int len);
void print_tcp_packet(unsigned char* Buffer, int Size);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void PrintData (unsigned char* data , int Size);

int main(int argc, char** argv)
{
    int cnt, op, i, done = 0;
    bpf_u_int32 localnet, netmask;
    char* cp, *cmdbuf, *device;
    struct bpf_program fcode;
    void (*oldhandler)(int);
    u_char* pcap_userdata;
    char ebuf[PCAP_ERRBUF_SIZE];

    cnt = -1;
    device = NULL;

    if ((cp = strrchr(argv[0], '/')) != NULL)
	program_name = cp + 1;
    else
	program_name = argv[0];

    opterr = 0;
    while ((i = getopt(argc, argv, "pa")) != -1) {
	switch (i) {
	case 'p':
	    pflag = 1;
	    break;
	case 'a':
	    aflag = 1;
	    break;
	case '?':
	default:
	    done = 1;
	    break;
	}
	if (done)
	    break;
    }
    if (argc > (optind))
	cmdbuf = copy_argv(&argv[optind]);
    else
	cmdbuf = "";
    if (device == NULL) {
	device = pcap_lookupdev(ebuf);
	if (device == NULL)
	    error("%s", ebuf);
    }
    pd = pcap_open_live(device, snaplen, 1, 1000, ebuf);
    if (pd == NULL)
	error("%s", ebuf);
    i = pcap_snapshot(pd);
    if (snaplen < i) {
	warning("snaplen raised from %d to %d", snaplen, i);
	snaplen = i;
    }
    if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
	localnet = 0;
	netmask = 0;
	warning("%s", ebuf);
    }
    /*
	 * Let user own process after socket has been opened.
	 */
    setuid(getuid());

    if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
	error("%s", pcap_geterr(pd));

    (void)setsignal(SIGTERM, program_ending);
    (void)setsignal(SIGINT, program_ending);
    /* Cooperate with nohup(1) */
    if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
	(void)setsignal(SIGHUP, oldhandler);

    if (pcap_setfilter(pd, &fcode) < 0)
	error("%s", pcap_geterr(pd));
    pcap_userdata = 0;
    (void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
    if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
	(void)fprintf(stderr, "%s: pcap_loop: %s\n",
	    program_name, pcap_geterr(pd));
	exit(1);
    }
    pcap_close(pd);
    exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
    struct pcap_stat stat;

    if (pd != NULL && pcap_file(pd) == NULL) {
	(void)fflush(stdout);
	putc('\n', stderr);
	if (pcap_stats(pd, &stat) < 0)
	    (void)fprintf(stderr, "pcap_stats: %s\n",
		pcap_geterr(pd));
	else {
	    (void)fprintf(stderr, "%d packets received by filter\n",
		stat.ps_recv);
	    (void)fprintf(stderr, "%d packets dropped by kernel\n",
		stat.ps_drop);
	}
    }
    (void)fprintf(stderr, "IP Packets: %d\nARP Packets: %d\nICMP Packts: %d\n", cnt_ip, cnt_arp, cnt_icmp);
    exit(0);
}

/* Like default_print() but data need not be aligned */
void default_print_unaligned(register const u_char* cp, register u_int length)
{
    register u_int i, s;
    register int nshorts;

    nshorts = (u_int)length / sizeof(u_short);
    i = 0;
    while (--nshorts >= 0) {
	if ((i++ % 8) == 0)
	    (void)printf("\n\t\t\t");
	s = *cp++;
	(void)printf(" %02x%02x", s, *cp++);
    }
    if (length & 1) {
	if ((i % 8) == 0)
	    (void)printf("\n\t\t\t");
	(void)printf(" %02x", *cp);
    }
}

/*
 * By default, print the packet out in hex.
 */
void default_print(register const u_char* bp, register u_int length)
{
    register const u_short* sp;
    register u_int i;
    register int nshorts;

    if ((long)bp & 1) {
	default_print_unaligned(bp, length);
	return;
    }
    sp = (u_short*)bp;
    nshorts = (u_int)length / sizeof(u_short);
    i = 0;
    while (--nshorts >= 0) {
	if ((i++ % 8) == 0)
	    (void)printf("\n\t");
	(void)printf(" %04x", ntohs(*sp++));
    }
    if (length & 1) {
	if ((i % 8) == 0)
	    (void)printf("\n\t");
	(void)printf(" %02x", *(u_char*)sp);
    }
}

/* here is our function, that prints decoded ethernet header 
	+ * p - ethernet frame
	+ * l - length
	+ */
void ethernet_print(const u_char* p, u_int len)
{
    u_int type;
	int i;
    arphdr_t* arpheader = NULL; /* Pointer to the ARP header              */
    arpheader = (struct arphdr*)(p + 14);

    // first 6 octets is a destination MAC address
    // next 6 octets is a source MAC address
    printf("DA: %02X:%02X:%02X:%02X:%02X:%02X ", p[6], p[7], p[8], p[9], p[10], p[11]);
    printf("SA: %02X:%02X:%02X:%02X:%02X:%02X ", p[0], p[1], p[2], p[3], p[4], p[5]);
    // accounting for broadcast packets (all FF destination MAC)
    if (p[6] == 0xFF && p[7] == 0xFF && p[8] == 0xFF && p[9] == 0xFF && p[10] == 0xFF && p[11] == 0xFF)
	cnt_broadcast++;
    // type or len field (2 bytes in network byte order)
    // if <= 1500 - length
    // if > 1536 - type
    type = p[12] * 256 + p[13];
    if (type <= 1500)
	printf("Len: %u", type);
    if (type > 1536)
	printf("Type: 0x%X ", type);
    if (type == (0x800))
	printf("Payload = IP"), cnt_ip++;
    if (type == (0x806))
	printf("Payload = ARP"), cnt_arp++;
	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x800) {
		printf("\n\tOperation: %s", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");	
		printf("\n\tSrc MAC: ");

		for (i = 0; i < 6; i++)
		    printf("%02X:", arpheader->sha[i]);

		printf("\n\tSrc IP: ");

		for (i = 0; i < 4; i++)
		    printf("%d.", arpheader->spa[i]);

		printf("\n\tDest MAC: ");

		for (i = 0; i < 6; i++)
		    printf("%02X:", arpheader->tha[i]);

		printf("\n\tDest IP: ");

		for (i = 0; i < 4; i++)
			printf("%d.", arpheader->tpa[i]);

		printf("");
    }
	else
	{
		struct sniff_ethernet *ethernet;
		ethernet = (struct sniff_ethernet*)(p);

		struct sniff_ip *ip;
		ip = (struct sniff_ip *)(p + 14);
		int size_ip = (ip->ip_vhl & 0x0f)*4;
		if(size_ip < 20){
			printf("Invalid Ip header length");
			return;
		}

		printf("\n\tFrom: %s\n", inet_ntoa(ip->ip_src));
		printf("\tTo: %s\n", inet_ntoa(ip->ip_dst));
		
		/* determine protocol */	
		switch(ip->ip_p) {
		case 6:
			printf("   \tProtocol: TCP\n");
			print_tcp_packet(p, (int) len);
			break;
		case 17:
			printf("   \tProtocol: UDP\n");
			return;
		case 1:
			printf("   \tProtocol: ICMP\n");
			cnt_icmp++;
			print_icmp_packet(p, (int) len);
			return;
		case 0:
			printf("   \tProtocol: IP\n");
			return;
		default:
			printf("   \tProtocol: unknown\n");
			return;
		}
		
		struct sniff_tcp *tcp;
		tcp = (struct sniff_tcp*)(p + SIZE_ETHERNET + size_ip);
		int size_tcp = (((tcp)->th_offx2 & 0xf0) >> 4) *4;
		if(size_tcp < 20){
			printf("\tInvalid TCP Header");
			return;
		}

		printf("\tSrc port: %d\n", ntohs(tcp->th_sport));
		printf("\tDst port: %d", ntohs(tcp->th_dport));
		
		/* define/compute tcp payload (segment) offset */
		char *payload = (u_char *)(p + SIZE_ETHERNET + size_ip + size_tcp);
		
		/* compute tcp payload (segment) size */
		int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);	
		if (size_payload > 0) {
					printf("\n\tPayload (%d bytes):\n", size_payload);
							print_payload(payload, size_payload);
								}
	}
}
/*
insert your code in this routine

*/

void raw_print(u_char* user, const struct pcap_pkthdr* h, const u_char* p)
{
    u_int length = h->len;
    u_int caplen = h->caplen;
    ethernet_print(p, caplen);
    //        default_print(p, caplen);
    putchar('\n');
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;
	/* data fits on one line */
	if (len <= line_width) {
		printf("\t");
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		printf("\t");
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("");

return;
}

void print_icmp_packet(const u_char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
             
    printf("ICMP Header\n");
    printf("   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11) 
        printf("  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == 0) 
        printf("  (ICMP Echo Reply)\n");
    printf("   |-Code : %d\n",(unsigned int)(icmph->code));
    printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
    printf("   |-ID       : %d\n",ntohs(icmph->id));
    printf("   |-Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
         
    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
         
    printf("IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    printf("TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    printf("Data Payload\n");  
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                         
    printf("\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
    int i, j; 
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra spaces
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}


