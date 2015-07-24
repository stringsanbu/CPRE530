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

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packettype;
int ip_packet_count = 0;
int arp_packet_count = 0;
int icmp_packet_count = 0;
int broadcast_packet_count = 0;

char *program_name;

/* Externs */
extern void bpf_dump(struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
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
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
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

	printf("\n");
	printf("ip packet count = %d\n", ip_packet_count);
	printf("arp packet count = %d\n", arp_packet_count);
	printf("icmp packet count = %d\n", icmp_packet_count)
	printf("broadcast packet count = %d\n", broadcast_packet_count);

	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
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
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

/*
insert your code in this routine

*/

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int i = 0;

    u_int length = h->len;
    u_int caplen = h->caplen;

    u_char type[2];
    u_short len;
    u_char sa[6];
    u_char da[6];

    //arp variables
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;
    uint16_t operation;
    u_char sender_hw_addr[6];
    u_char sender_prot_addr[4];
    u_char receiver_hw_addr[6];
    u_char receiver_prot_addr[4];


    //copy over the ethtype (or length)
    memcpy(type, &p[12], 2);
    len = (u_short) (type[0] << 8 | type[1]);

    //copy over addresses (source and dest)
    memcpy(da, p, 6);
    memcpy(sa, &p[6], 6);

    //print out destination address
    printf("DA = %02X", p[0]);
    for(i = 1; i < 6; i++)
    {
    	printf(":%02X", p[i]);
    }

    //print out source address
    printf(" SA = %02X", p[6]);
    for(i = 7; i < 12; i++)
    {
    	printf(":%02X", p[i]);
    }

    //if the destination address is FF:FF:FF:FF:FF:FF then increment broadcast count
    if(da[0] == 0xFF && da[1] == 0xFF && da[2] == 0xFF && da[3] == 0xFF &&
    	da[4] == 0xFF && da[5] == 0xFF)
    {
    	broadcast_packet_count++;
    }

    //if length is >= 0x0600 then it is a type, else it is a length and print it out as decimal
    if(len >= 1536)
    {
    	//if type is 0x0800 then payload is IP
    	if(type[0] == 8 && type[1] == 0)
    	{
    		printf(" payload = IP\n");
    		ip_packet_count++;
    	}
    	//if type is 0x0806 then payload is ARP
    	else if(type[0] == 8 && type[1] == 6)
    	{
    		printf(" payload = ARP\n");
    		printf("Hardware Type: %x", )
    		arp_packet_count++;
    	}
    	//else just print out type in hex
    	else
    	{
    		printf(" type = %02x%02x", type[0], type[1]);
    	}
    }
    else
    {
    	printf(" length = %02X%02X", type[0], type[1]);
    }

    printf(" packet size = %d", caplen);
    sleep(2);

    //default_print(p, caplen);
    putchar('\n');
}

