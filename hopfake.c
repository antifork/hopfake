/*
 *  $Id$
 *
 *  
 *  Copyright (c) 2003 Dallachiesa Michele <xenion@antifork.org>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * sizeof_datalink() function from aping@awgn and other stuff from
 * rawicmp@buffer
 */

#define __USE_BSD
#define _GNU_SOURCE		/* needed by vasprintf */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>
#include "bpf.h"


#define MYTTL 65
#define KNTTL 64

#define IPTABLES_PATH "/usr/sbin/iptables "
#define REDNULL " > /dev/null 2> /dev/null"
#define SYSTEM_RULES(x) { mysystem(IPTABLES_PATH "-%c OUTPUT -s %s -p icmp --icmp-type port-unreachable -m ttl --ttl %d -j DROP" REDNULL,x,ipfromlong(interface_addr),KNTTL); mysystem(IPTABLES_PATH "-%c OUTPUT -s %s -p icmp --icmp-type echo-reply -m ttl --ttl %d -j DROP" REDNULL,x,ipfromlong(interface_addr),KNTTL); }

// #define DEBUG

#ifndef DEBUG
#define LOG(arg...) syslog(LOG_DAEMON | LOG_INFO, ## arg)
#else
#define LOG(arg...) {printf(## arg);printf("\n");}
#endif

#define VERSION "1.5"

#define SIZEOF_IPHEADER(x) ((x->ip_hl) << 2)
#define SIZEOF_IPOPTIONS(x) (SIZEOF_IPHEADER(x)-sizeof(struct ip))

#define CASE(x,y) { case (x): return y; break; }

#define SIG_NAME(x) x == SIGURG  ? "SIGURG"  : \
                    x == SIGPIPE ? "SIGPIPE" : \
                    x == SIGQUIT ? "SIGQUIT" : \
                    x == SIGINT  ? "SIGINT"  : \
                    x == SIGTERM ? "SIGTERM" : \
                    x == SIGHUP  ? "SIGHUP"  : \
                    x == SIGSEGV ? "SIGSEGV" : \
                    x == SIGBUS  ? "SIGBUS"  : "UNKNOWN"

#define ICMPCODE_NAME(x) x ==  0 ? "bad net"           : \
                         x ==  1 ? "bad host"          : \
                         x ==  2 ? "bad protocol"      : \
                         x ==  3 ? "bad port"          : \
                         x ==  4 ? "IP_DF caused drop" : \
                         x ==  5 ? "src route failed"  : \
                         x ==  6 ? "unknown net"       : \
                         x ==  7 ? "unknown host"      : \
                         x ==  8 ? "src host isolated" : \
                         x ==  9 ? "net denied"        : \
                         x == 10 ? "host denied"       : \
                         x == 11 ? "bad tos for net"   : \
                         x == 12 ? "bad tos for host"  : \
                         x == 13 ? "admin prohib"      : \
                         x == 14 ? "host prec vio."    : \
                         x == 15 ? "prec cutoff"       : "UNKNOWN"


void            fatal(char *, ...);
int             sizeof_datalink(pcap_t * p);
u_int32_t       fake_addr(int ttl);
void            sigdie(int signo);
char           *ipfromlong(unsigned long s_addr);
u_int32_t       get_interface_addr(char *interface);
unsigned short  in_cksum(unsigned short *addr, int len);
void            init_opt(int argc, char **argv);
void            help();
int             mysystem(char *pattern, ...);


FILE           *f = NULL;
pcap_t         *p = NULL;
char            errbuf[PCAP_ERRBUF_SIZE];
int             fakefinalhop = 0;
int             finalhop_unreachable = 0;
char           *interface = NULL;
u_int32_t       interface_addr = INADDR_NONE;
u_int8_t        unreach_icmp_code = 1;	/* bad host, used with '?' type
					 * traceroutes. */

int
main(int argc, char **argv)
{
    u_char          buf[1024 * 4];
    const u_char   *packet;
    struct bpf_program bpf_filter;
    struct pcap_pkthdr pkthdr;
    struct sockaddr_in to;
    struct ip      *ip,
                   *pktip;
    struct icmp    *icmp,
                   *pkticmp;
    int             dlsize,
                    n_fake_hops,
                    s,
                    z,
                    pktsize;
    char            type;


    signal(SIGBUS, sigdie);
    signal(SIGSEGV, sigdie);
    signal(SIGINT, sigdie);
    signal(SIGTERM, sigdie);

    if (argc == 1)
	help();

    init_opt(argc, argv);

    interface_addr = get_interface_addr(interface);

    SYSTEM_RULES('I');

#ifndef DEBUG
    if (fork())
	exit(0);
#endif

    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	fatal("socket(): %s", strerror(errno));

    z = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &z, sizeof(z)) < 0)
	fatal("setsockopt(): %s", strerror(errno));

    if ((p = pcap_open_live(interface, 8192, 0, 0, errbuf)) == NULL)
	fatal("pcap_open_live(): %s", errbuf);

    sprintf(buf, "ip dst %s", ipfromlong(interface_addr));

    if (pcap_compile(p, &bpf_filter, buf, 0, 0) < 0)
	fatal("pcap_compile(): %s", pcap_geterr(p));

    if (pcap_setfilter(p, &bpf_filter) < 0)
	fatal("pcap_setfilter(): %s", pcap_geterr(p));

    pcap_freecode(&bpf_filter);

    if ((dlsize = sizeof_datalink(p)) < 0)
	fatal("known datalink type but unknown datalink header size");

    /*
     * get n_fake_hops and test hops 
     */

    for (n_fake_hops = 0; fgets(buf, sizeof buf, f);)
	if ('0' <= *buf && *buf <= '9')
	    ++n_fake_hops;

    if (n_fake_hops < 1)
	fatal("hops-file broken !");

    for (z = 0; z < n_fake_hops; ++z)
	fake_addr(z + 1);

    LOG("starting HopFake");
    LOG("%d fake hops loaded", n_fake_hops);
    if (fakefinalhop)
	LOG("last-hop faking enabled");
    if (finalhop_unreachable)
	LOG("last-hop unreachable enabled");
    LOG("listening for traceroutes on %s.", interface);

    if (fakefinalhop)
	n_fake_hops--;

    ip = (struct ip *) buf;
    icmp = (struct icmp *) ((void *) buf + sizeof(struct ip));

    srand(getpid());

    for (;;) {

	usleep(1);

	if (!(packet = pcap_next(p, &pkthdr)))
	    continue;
	if (pkthdr.caplen != pkthdr.len)
	    continue;

	pkthdr.caplen -= dlsize;
	packet += dlsize;

	pktip = (struct ip *) ((void *) packet);

	if (pktip->ip_p == IPPROTO_ICMP) {
	    pkticmp =
		(struct icmp *) ((void *) packet + SIZEOF_IPHEADER(pktip));
	    if (pkticmp->icmp_type == ICMP_ECHO
		&& pktip->ip_ttl > n_fake_hops + 1)
		pktip->ip_ttl = n_fake_hops + 1;	/* thanks Thor */
	}


	if (pktip->ip_ttl <= n_fake_hops + 1) {

	    switch (pktip->ip_p) {

	    case IPPROTO_ICMP:
		if (pkticmp->icmp_type != ICMP_ECHO
		    || pkthdr.caplen > sizeof buf)
		    type = '?';
		else
		    type = 'E';
		break;

	    case IPPROTO_UDP:
		type = 'U';
		break;

	    case IPPROTO_TCP:
		type = 'T';
		break;

	    default:
		type = '?';
		break;
	    }

	    if (pktip->ip_ttl == 1)
		LOG("detected traceroute from %s (%c)",
		    ipfromlong(pktip->ip_src.s_addr), type);

	    if (pktip->ip_ttl == n_fake_hops + 1) {

		if (finalhop_unreachable)
		    type = '?';

		switch (type) {

		case 'U':
		case 'T':
		    icmp->icmp_type = ICMP_DEST_UNREACH;
		    icmp->icmp_code = ICMP_UNREACH_PORT;
		    type = '?';
		    break;

		case 'E':
		    memcpy(ip, pktip, pkthdr.caplen);
		    icmp->icmp_type = ICMP_ECHOREPLY;
		    icmp->icmp_code = 0;
		    pktsize = pkthdr.caplen;
		    break;

		case '?':
		    icmp->icmp_type = ICMP_DEST_UNREACH;
		    icmp->icmp_code = unreach_icmp_code;
		    break;
		}

		if (fakefinalhop)
		    ip->ip_src.s_addr = fake_addr(n_fake_hops + 1);
		else
		    ip->ip_src.s_addr = interface_addr;

	    } else {
		ip->ip_src.s_addr = fake_addr(pktip->ip_ttl);
		icmp->icmp_type = ICMP_TIME_EXCEEDED;
		icmp->icmp_code = ICMP_EXC_TTL;
		type = '?';
	    }

	    if (type == '?') {
		ip->ip_v = IPVERSION;
		ip->ip_hl = 5;
		ip->ip_tos = 0;
		ip->ip_id = rand();
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_off = htons(IP_DF);

		memcpy(&(icmp->icmp_ip), pktip,
		       SIZEOF_IPHEADER(pktip) + 8);
		pktsize =
		    sizeof(struct ip) + sizeof(struct icmp) +
		    SIZEOF_IPOPTIONS(pktip) + 8;

		icmp->icmp_ip.ip_ttl = 1;
		icmp->icmp_id = getpid() & 0xffff;
		icmp->icmp_seq = rand();
	    }

	    ip->ip_dst.s_addr = pktip->ip_src.s_addr;
	    ip->ip_ttl = MYTTL;
	    ip->ip_sum = 0;
	    ip->ip_len = htons(pktsize);

	    icmp->icmp_cksum = 0;
	    icmp->icmp_cksum =
		in_cksum((unsigned short *) icmp,
			 pktsize - SIZEOF_IPHEADER(ip));
	    if (icmp->icmp_cksum == 0)
		icmp->icmp_cksum = 0xffff;

	    to.sin_family = AF_INET;
	    to.sin_addr.s_addr = ip->ip_dst.s_addr;

	    usleep(pktip->ip_ttl * 2);	// latency ..

	    z = sendto(s, (void *) buf,
		       pktsize,
		       0, (struct sockaddr *) &to,
		       sizeof(struct sockaddr));

	    if (z < 0)
		fatal("sendto(): %s", strerror(errno));


	}
    }

    /*
     * never reached 
     */

    return 0;
}


u_int32_t
fake_addr(int ttl)
{
    int             i;
    struct in_addr  inp;
    static char     line[100];

    rewind(f);

    for (i = 0; i < ttl;) {
	if (fgets(line, sizeof line, f) == NULL)
	    fatal("fake_addr(): hops-file broken");
	if ('0' <= *line && *line <= '9')
	    ++i;
    }

    for (i = 0; line[i] != '\0' && line[i] != '\n'; ++i);
    line[i] = '\0';

    if (inet_aton(line, &inp) == 0)
	fatal("inet_aton(), hops-file broken");

    return inp.s_addr;

}


int
sizeof_datalink(pcap_t * p)
{
    int             dtl;

    if ((dtl = pcap_datalink(p)) < 0)
	fatal("pcap_datalink(): %s", pcap_geterr(p));

    switch (dtl) {

	CASE(AP_DLT_NULL, 4);
	CASE(AP_DLT_EN10MB, 14);
	CASE(AP_DLT_EN3MB, 14);
	CASE(AP_DLT_AX25, -1);
	CASE(AP_DLT_PRONET, -1);
	CASE(AP_DLT_CHAOS, -1);
	CASE(AP_DLT_IEEE802, 22);
	CASE(AP_DLT_ARCNET, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__BSDI__)
	CASE(AP_DLT_SLIP, 16);
#else
	CASE(AP_DLT_SLIP, 24);
#endif

#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
	CASE(AP_DLT_PPP, 4);
#elif defined (__sun)
	CASE(AP_DLT_PPP, 8);
#else
	CASE(AP_DLT_PPP, 24);
#endif
	CASE(AP_DLT_FDDI, 21);
	CASE(AP_DLT_ATM_RFC1483, 8);

	CASE(AP_DLT_LOOP, 4);	/* according to OpenBSD DLT_LOOP
				 * collision: see "bpf.h" */
	CASE(AP_DLT_RAW, 0);

	CASE(AP_DLT_SLIP_BSDOS, 16);
	CASE(AP_DLT_PPP_BSDOS, 4);
	CASE(AP_DLT_ATM_CLIP, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
	CASE(AP_DLT_PPP_SERIAL, 4);
	CASE(AP_DLT_PPP_ETHER, 4);
#elif defined (__sun)
	CASE(AP_DLT_PPP_SERIAL, 8);
	CASE(AP_DLT_PPP_ETHER, 8);
#else
	CASE(AP_DLT_PPP_SERIAL, 24);
	CASE(AP_DLT_PPP_ETHER, 24);
#endif
	CASE(AP_DLT_C_HDLC, -1);
	CASE(AP_DLT_IEEE802_11, 30);
	CASE(AP_DLT_LINUX_SLL, 16);
	CASE(AP_DLT_LTALK, -1);
	CASE(AP_DLT_ECONET, -1);
	CASE(AP_DLT_IPFILTER, -1);
	CASE(AP_DLT_PFLOG, -1);
	CASE(AP_DLT_CISCO_IOS, -1);
	CASE(AP_DLT_PRISM_HEADER, -1);
	CASE(AP_DLT_AIRONET_HEADER, -1);

    default:
	fatal("unknown datalink type DTL_?=%d", dtl);
	break;
    }

    return 0;
}


char
               *
ipfromlong(unsigned long s_addr)
{
    struct in_addr  myaddr;

    myaddr.s_addr = s_addr;
    return inet_ntoa(myaddr);
}


void
fatal(char *pattern, ...)
{
    va_list         ap;
    int             len;
    char           *p;

    va_start(ap, pattern);
    len = vasprintf(&p, pattern, ap);
    va_end(ap);

    if (len > 0) {
	LOG("%s; exit forced.\n", p);
	free(p);
    }

    if (interface_addr != INADDR_NONE)
	SYSTEM_RULES('D');

    exit(1);
}


void
sigdie(int signo)
{
    LOG("caught %s signal (%d), cleaning up\n", SIG_NAME(signo), signo);
    SYSTEM_RULES('D');

    if (interface)
	free(interface);
    if (f)
	fclose(f);
    if (p)
	pcap_close(p);

    exit(0);
}


unsigned short
in_cksum(unsigned short *addr, int len)
{
    register int    nleft = len;
    register unsigned short *w = addr;
    register unsigned short answer;
    register int    sum = 0;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1) {
	sum += *w++;
	nleft -= 2;
    }

    /*
     * mop up an odd byte, if necessary 
     */
    if (nleft == 1)
	sum += *(u_char *) w;
    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);		/* add carry */
    answer = ~sum;		/* truncate to 16 bits */
    return (answer);
}


void
init_opt(int argc, char **argv)
{
    int             c;

    while ((c = getopt(argc, argv, "i:c:u:lh")) != EOF)
	switch (c) {

	case 'i':
	    interface = strdup(optarg);
	    break;

	case 'c':
	    if (!f)
		if ((f = fopen(optarg, "r")) == NULL)
		    fatal("unable to open hops-file");
	    break;

	case 'l':
	    fakefinalhop = 1;
	    break;

	case 'u':
	    if (*optarg < '0' || *optarg > '9')
		fatal("-u requires an icmp code");
	    unreach_icmp_code = atoi(optarg);
	    finalhop_unreachable = 1;
	    break;

	case 'h':
	    help();

	default:
	    fatal("try -h");
	}

    if (!interface)
	fatal("interface required");
    if (!f)
	fatal("hops-file required");

    if (unreach_icmp_code > 15)
	fatal("unreachable icmp code not valid");
}


void
help()
{
    int             i;

    printf("hopfake v%s by xenion@antifork.org\n\n", VERSION);
    printf("USAGE: hopfake [options]\n\n");
    printf("-i interface                        listen on interface\n");
    printf("-c hops-file                        the hops-file pathname\n");
    printf("-l                                  enable last-hop faking\n");
    printf("-u code                             last-hop unreachable\n");
    printf("-h                                  this\n\n");
    printf("values for code:\n\n");

    for (i = 0; i < 16; i += 2)
	printf("%2d  %-20s  %2d  %s\n", i, ICMPCODE_NAME(i), i + 1,
	       ICMPCODE_NAME(i + 1));
    printf("\n");
    exit(0);
}


int
mysystem(char *pattern, ...)
{
    char           *s;
    va_list         ap;
    int             len,
                    z;

    va_start(ap, pattern);
    len = vasprintf(&s, pattern, ap);
    va_end(ap);

    if (len > 0) {

#ifdef DEBUG
	printf("# %s\n", s);
#endif
	z = system(s);
	free(s);
    } else
	z = -2;

    return z;
}


u_int32_t
get_interface_addr(char *ifname)
{				/* thanks awgn ;)
				 * http://awgn.antifork.org/codes/if.c */
    char            buffer[10240];
    int             sd;
    struct ifreq   *ifr,
                   *iflast;
    struct ifconf   ifc;
    struct sockaddr_in *ptr_if;


    memset(buffer, 0, 10240);

    /*
     * dummy dgram socket for ioctl 
     */

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	fatal("socket(): %s", strerror(errno));

    ifc.ifc_len = sizeof(buffer);
    ifc.ifc_buf = buffer;

    /*
     * getting ifs: this fills ifconf structure. 
     */

    if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
	close(sd);
	fatal("ioctl(): %s", strerror(errno));
    }

    close(sd);

    /*
     * line_up ifreq structure 
     */

    ifr = (struct ifreq *) buffer;
    iflast = (struct ifreq *) ((char *) buffer + ifc.ifc_len);

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	fatal("socket(): %s", strerror(errno));

#if HAVE_SOCKADDR_SALEN
    for (; ifr < iflast;
	 (char *) ifr += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len)
#else
    for (; ifr < iflast;
	 (char *) ifr +=
	 sizeof(ifr->ifr_name) + sizeof(struct sockaddr_in))
#endif
    {
	if (*(char *) ifr) {
	    ptr_if = (struct sockaddr_in *) &ifr->ifr_addr;

	    if (!strcmp(ifname, ifr->ifr_name)) {
		close(sd);
		return (ptr_if->sin_addr.s_addr);
	    }


	}
    }

    close(sd);
    return INADDR_NONE;
}

/*
 * EOF 
 */
