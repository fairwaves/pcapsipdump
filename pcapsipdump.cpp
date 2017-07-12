/*
    This file is part of pcapsipdump

    pcapsipdump is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    pcapsipdump is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    ---

    Project's home: http://pcapsipdump.sf.net/
*/

#ifdef sparc
#define __BIG_ENDIAN 1
#endif
#ifndef sparc
#include <endian.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <regex.h>
#include <libgen.h>

#ifdef USE_BSD_STRING_H
#include <bsd/string.h>
#else
#define strlcpy strncpy
#endif

#include <pcap.h>

#include "calltable.h"
#include "trigger.h"
#include "pcapsipdump.h"
#include "pcapsipdump_strlib.h"
#include "pcapsipdump_lib.h"

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

int get_sip_peername(char *data, int data_len, const char *tag, char *caller, int caller_len);
int get_ip_port_from_sdp(const char *sdp, size_t sdplen, in_addr_t *addr, unsigned short *port);
uint32_t get_ssrc (void *ip_packet_data, bool is_rtcp);
long long parse_size_string(char *s);
#ifndef _GNU_SOURCE
void *memmem(const void* haystack, size_t hl, const void* needle, size_t nl);
#endif

calltable *ct;
int verbosity=0;
int opt_t38only=0;

void sigint_handler(int param)
{
    printf("SIGINT received, terminating\n");
    ct->do_cleanup(0);
    exit(1);
}

void sigterm_handler(int param)
{
    printf("SIGTERM received, terminating\n");
    ct->do_cleanup(0);
    exit(1);
}

#define RTPSAVE_NONE 0
#define RTPSAVE_RTP 1
#define RTPSAVE_RTP_RTCP 2
#define RTPSAVE_RTPEVENT 3
#define MAX_PCAP_FILTER_EXPRESSION 1024

/* return 32-bit hash of source/dest IPv4 or IPv6 address based on IP header */
uint32_t hsaddr(void *p) {
    struct iphdr *header_ip = (iphdr*)p;
    struct ipv6hdr *header_ipv6 = (ipv6hdr*)p;
    if(header_ip->version == 4){
        return header_ip->saddr;
    }else{
        // Ad-hoc 128bit -> 32bit hash function
        return (uint32_t)(
            (uint32_t)(header_ipv6->saddr.s6_addr32[0])+
            (uint32_t)(header_ipv6->saddr.s6_addr32[1]*19)+
            (uint32_t)(header_ipv6->saddr.s6_addr32[2]*37)+
            (uint32_t)(header_ipv6->saddr.s6_addr32[3]*109));
    }
}

uint32_t hdaddr(void *p) {
    struct iphdr *header_ip = (iphdr*)p;
    struct ipv6hdr *header_ipv6 = (ipv6hdr*)p;
    if(header_ip->version == 4){
        return header_ip->daddr;
    }else{
        // Ad-hoc 128bit -> 32bit hash function
        return (uint32_t)(
            (uint32_t)(header_ipv6->daddr.s6_addr32[0])+
            (uint32_t)(header_ipv6->daddr.s6_addr32[1]*19)+
            (uint32_t)(header_ipv6->daddr.s6_addr32[2]*37)+
            (uint32_t)(header_ipv6->daddr.s6_addr32[3]*109));
    }
}

bool get_method(const char *data, char *sip_method, size_t sip_method_size) {
    char *p;
    memcpy(sip_method, data, sip_method_size - 1);
    sip_method[sip_method_size - 1] = ' ';
    p = strchr(sip_method, ' ');
    if (p != NULL) {
       *p = '\0';
       for (char *c = sip_method; c < p; c++){
            if (!isupper(*c))
                goto fail;
       }
        return true;
    }
fail:
    sip_method[0] = '\0';
    return false;
}

int parse_sdp(const char *sdp, size_t sdplen, calltable_element *ce)
{
    in_addr_t addr;
    unsigned short port;
    if (! get_ip_port_from_sdp(sdp, sdplen, &addr, &port)){
        ct->add_ip_port(ce, addr, port);
    }else{
        if (verbosity >= 2) {
            printf("Can't get ip/port from SDP:\n%s\n\n", sdp);
            return -1;
        }
    }
    unsigned char rtpmap_event = sdp_get_rtpmap_event(sdp);
    if (rtpmap_event) {
        ce->rtpmap_event = rtpmap_event;
    }
    if (opt_t38only && memmem(sdp, sdplen, "udptl t38", 9)!=NULL){
        ce->had_t38=1;
    }
    return 0;
}

int main(int argc, char *argv[])
{

    pcap_t *handle;/* Session handle */
    // directory/filename template, where .pcap files are written
    char *opt_fntemplate = (char *)"/var/spool/pcapsipdump/%Y%m%d/%H/%Y%m%d-%H%M%S-%f-%t-%i.pcap";
    char *ifname;/* interface to sniff on */
    char *fname;/* pcap file to read on */
    char errbuf[PCAP_ERRBUF_SIZE];/* Error string */
    struct bpf_program fp;/* The compiled filter */
#ifdef USE_TCP
    char filter_exp[MAX_PCAP_FILTER_EXPRESSION] = "udp or tcp or vlan";/* The filter expression */
#else
    char filter_exp[MAX_PCAP_FILTER_EXPRESSION] = "udp or vlan";/* The filter expression */
#endif
    struct pcap_pkthdr *pkt_header; /* The header that pcap gives us */
    const u_char *pkt_data; /* The actual packet */
    unsigned long last_cleanup=0;
    int res;
    int offset_to_ip=0;
    int opt_fork=1;
    int opt_promisc=1;
    int opt_packetbuffered=0;
    int opt_rtpsave=RTPSAVE_RTP_RTCP;
    int opt_call_skip_n=1; /* By default, record every first call, i.e. record all */
    int call_skip_cnt=1;
    int opt_pcap_buffer_size=0; /* Operating system capture buffer size, a.k.a. libpcap ring buffer size */
    int opt_absolute_timeout = INT32_MAX;
    in_addr_t opt_nat_to_addr = INADDR_NONE;
    bool opt_do_nat_to = false;
    bool number_filter_matched=false;
    regex_t number_filter, method_filter;
    regmatch_t pmatch[1];
    number_filter.allocated=0;
    const char *pid_file="/var/run/pcapsipdump.pid";

    ifname=NULL;
    fname=NULL;
    regcomp(&method_filter, "^(INVITE|OPTIONS|REGISTER)$", REG_EXTENDED);
    trigger.init();

    while(1) {
        signed char c;

        c = getopt (argc, argv, "i:r:d:v:m:n:N:R:l:B:T:t:fpU");
        if (c == -1)
            break;

        switch (c) {
            case 'i':
                ifname=optarg;
                break;
            case 'v':
                verbosity = atoi(optarg);
                trigger.verbosity = verbosity;
                break;
            case 'm':
                regfree(&method_filter);
                regcomp(&method_filter, optarg, REG_EXTENDED);
                break;
            case 'n':
                regcomp(&number_filter, optarg, REG_EXTENDED);
                break;
            case 'R':
                if (strcasecmp(optarg,"none")==0){
                    opt_rtpsave=RTPSAVE_NONE;
                }else if (strcasecmp(optarg,"rtpevent")==0){
                    opt_rtpsave=RTPSAVE_RTPEVENT;
                }else if (strcasecmp(optarg,"t38")==0){
                    opt_t38only=1;
                }else if (strcasecmp(optarg,"all")==0 ||
                          strcasecmp(optarg,"rtp+rtcp")==0){
                    opt_rtpsave=RTPSAVE_RTP_RTCP;
                }else if (strcasecmp(optarg,"rtp")==0){
                    opt_rtpsave=RTPSAVE_RTP;
                }else{
                    printf("Unrecognized RTP filter specification: '%s'\n",optarg);
                    return 1;
                }
                break;
            case 'l':
                opt_call_skip_n=atoi(optarg);
                if (opt_call_skip_n<1){
                    fprintf(stderr, "Invalid option '-l %s'. Argument should be positive integer.\n", optarg);
                    return(1);
                }
                break;
            case 'B':
                opt_pcap_buffer_size = parse_size_string(optarg);
                if (opt_pcap_buffer_size < 1){
                    fprintf(stderr, "Invalid option '-B %s'.\n"
                                    "  Argument should be positive integer with optional quantifier.\n"
                                    "  e.g.: '-B 32768' or '-B 10KB' or '-b 512MiB', etc.\n", optarg);
                    return(1);
                }
                break;
            case 'r':
                fname=optarg;
                break;
            case 'd':
                opt_fntemplate = optarg;
                break;
            case 'f':
                opt_fork=0;
                break;
            case 'p':
                opt_promisc=0;
                break;
            case 'U':
                opt_packetbuffered=1;
                break;
            case 'T':
                opt_absolute_timeout = atol(optarg);
                break;
            case 't':
                trigger.add(optarg);
                break;
            case 'N':
                opt_do_nat_to = true;
                opt_nat_to_addr = inet_addr(optarg);
                break;
        }
    }

    // everything that is left unparsed in argument string is pcap filter expression
    if (optind < argc) {
        filter_exp[0]='\0';
        while (optind < argc) {
            if (filter_exp[0]!='\0'){
                strcat(filter_exp," ");
            }
            strcat(filter_exp,argv[optind++]);
        }
    }

    if (((fname==NULL)&&(ifname==NULL)) || (opt_do_nat_to && (opt_nat_to_addr == INADDR_NONE))){
	printf( "pcapsipdump version %s\n"
		"Usage: pcapsipdump [-fpUt] [-i <interface> | -r <file>] [-d <working directory>]\n"
                "                   [-v level] [-R filter] [-m filter] [-n filter] [-l filter]\n"
                "                   [-B size] [-T limit] [-t trigger:action:param] [expression]\n"
		" -f   Do not fork or detach from controlling terminal.\n"
		" -p   Do not put the interface into promiscuous mode.\n"
		" -U   Make .pcap files writing 'packet-buffered' - slower method,\n"
		"      but you can use partitially written file anytime, it will be consistent.\n"
		" -i   Specify network interface name (i.e. eth0, em1, ppp0, etc).\n"
		" -r   Read from .pcap file instead of network interface.\n"
		" -v   Set verbosity level (higher is more verbose).\n"
		" -B   Set the operating system capture buffer size, a.k.a. ring buffer size.\n"
		"      This can be expressed in bytes/KB(*1000)/KiB(*1024)/MB/MiB/GB/GiB. ex.: '-B 64MiB'\n"
		"      Set this to few MiB or more to avoid packets dropped by kernel.\n"
		" -R   RTP filter. Specifies what kind of RTP information to include in capture:\n"
		"      'rtp+rtcp' (default), 'rtp', 'rtpevent', 't38', or 'none'.\n"
		" -m   Method-filter. Default is '^(INVITE|OPTIONS|REGISTER)$'\n"
		" -n   Number-filter. Only calls to/from specified number will be recorded\n"
		"      Argument is a regular expression. See 'man 7 regex' for details.\n"
                " -l   Record only each N-th call (i.e. '-l 3' = record only each third call)\n"
                " -d   Set directory (or filename template), where captured files will be stored.\n"
                "      ex.: -d /var/spool/pcapsipdump/%%Y%%m%%d/%%H/%%Y%%m%%d-%%H%%M%%S-%%f-%%t-%%i.pcap\n"
                " -T   Unconditionally stop recording a call after it was active for this many seconds.\n"
                "      Might be useful for broken peers that keep sending RTP long after call ended.\n"
                " -t   <trigger>:<action>:<parameter>. Parameter is %%-expanded (see below)\n"
                "      Triggers: open = when opening a new .pcap file; close = when closing\n"
                "      Actions and their parameters:\n"
                "      mv:<directory> - move .pcap files to <directory> (using /bin/mv)\n"
                "      exec:\"/bin/blah args...\" - fork and execute /bin/blah with arguments\n"
                "      sh:\"shell code\" - fork and execute /bin/sh -c \"shell code\"\n"
        " -N   <ip-addr> Assume the RTP receiver is at this IP instead of at what's in c= in the sdp.\n"
                " *    Following %%-codes are expanded in -d and -t: %%f (from/caller), %%t (to/callee),\n"
                "      %%i (call-id), and call date/time (see 'man 3 strftime' for details)\n"
                " *    Trailing argument is pcap filter expression syntax, see 'man 7 pcap-filter'\n"
                , PCAPSIPDUMP_VERSION);
	return 1;
    }

    if ((res = opts_sanity_check_d(&opt_fntemplate)) != 0) return res;
    ct = new calltable;
    ct->opt_absolute_timeout = opt_absolute_timeout;
    if (opt_t38only){
        ct->erase_non_t38=1;
    }

    signal(SIGINT,sigint_handler);
    signal(SIGTERM,sigterm_handler);

    if (verbosity>=3){
        printf("Using pcap filter: '%s'\n",filter_exp);
    }

    if (ifname){
        handle = pcap_create(ifname,errbuf);
        if (handle == NULL){
            fprintf(stderr, "Couldn't open interface '%s': pcap_create(): %s\n", ifname, errbuf);
            return(2);
        }
        if (pcap_set_snaplen(handle, 9000)){
            fprintf(stderr, "Couldn't open interface '%s': pcap_set_snaplen(9000): %s\n", ifname, pcap_geterr(handle));
            return(2);
        }
        if (pcap_set_promisc(handle, opt_promisc)){
            fprintf(stderr, "Couldn't open interface '%s': pcap_set_promisc(opt_promisc): %s\n", ifname, pcap_geterr(handle));
            return(2);
        }
        if (pcap_set_timeout(handle, 1000)){
            fprintf(stderr, "Couldn't open interface '%s': pcap_set_timeout(1000):) %s\n", ifname, pcap_geterr(handle));
            return(2);
        }
        printf("Capturing on interface: %s\n", ifname);
        if (opt_pcap_buffer_size > 0){
            /* setting pcap_set_buffer_size to bigger values helps to deal with packet drops under high load
               libpcap > 1.0.0 if required for pcap_set_buffer_size
               for libpcap < 1.0.0 instead, this should be controled by /proc/sys/net/core/rmem_default
            */
            if(pcap_set_buffer_size(handle, opt_pcap_buffer_size)){
                fprintf(stderr, "Couldn't open interface '%s': pcap_set_buffer_size(): %s\n", ifname, pcap_geterr(handle));
                return(2);
            }
        }
        if(pcap_activate(handle)){
            fprintf(stderr, "Couldn't open interface '%s': pcap_activate(): %s\n", ifname, pcap_geterr(handle));
            return(2);
        }
    }else{
        printf("Reading file: %s\n", fname);
        handle = pcap_open_offline(fname, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open pcap file '%s': %s\n", fname, errbuf);
            return(2);
        }
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    {
	int dlt=pcap_datalink(handle);
	switch (dlt){
	    case DLT_EN10MB :
		offset_to_ip=sizeof(struct ether_header);
		break;
	    case DLT_LINUX_SLL :
		offset_to_ip=16;
		break;
	    case DLT_RAW :
		offset_to_ip=0;
		break;
	    default : {
		fprintf(stderr, "Unknown interface type (%d).\n", dlt);
		return 3;
	    }
	}
    }

    if (opt_fork){
        // daemonize

        pid_t pid = fork();
        if (pid) {
             FILE *fp = fopen(pid_file, "w");
             if (fp) {
                 fprintf(fp, "%d\n", pid);
                 fclose(fp);
                 exit(0);
             }else{
                 fprintf(stderr, "Can't write PID %d to file %s\n",
                         pid, pid_file);
                 return(2);
             }
        }
    }

    /* Retrieve the packets */
    while((res = pcap_next_ex( handle, &pkt_header, &pkt_data)) >= 0){
	{
	    struct iphdr *header_ip;
	    struct ipv6hdr *header_ipv6;
	    char *data;
	    const char *s;
	    unsigned long datalen;
	    unsigned long l;
	    int idx=-1;
            char sip_method[10] = "";

            if(res == 0)
                /* Timeout elapsed */
                continue;

	    if (pkt_header->ts.tv_sec-last_cleanup>15){
		if (last_cleanup>=0){
		    ct->do_cleanup(pkt_header->ts.tv_sec);
		}
		last_cleanup=pkt_header->ts.tv_sec;
	    }
            header_ip = (iphdr *)((char*)pkt_data + offset_to_ip);
            // 802.1Q VLAN
            if ((offset_to_ip == 14) &&
                ntohs(*((uint16_t*)((char*)pkt_data + offset_to_ip - 2))) == 0x8100 &&
                ntohs(*((uint16_t*)((char*)pkt_data + offset_to_ip + 2))) == 0x0800) {
                header_ip = (iphdr *)((char*)pkt_data + offset_to_ip + 4);
            }
            header_ipv6=(ipv6hdr *)header_ip;
            if ( /* sane IPv4 UDP */
                 (header_ip->version == 4 && pkt_header->caplen >=
                   (offset_to_ip+sizeof(struct iphdr)+sizeof(struct udphdr)) &&
                   header_ip->protocol == IPPROTO_UDP)
                 /* sane IPv6 UDP */ ||
                 (header_ipv6->version == 6 && pkt_header->caplen >=
                   (offset_to_ip+sizeof(struct ipv6hdr)+sizeof(struct udphdr)) &&
                   header_ipv6->nexthdr == IPPROTO_UDP)
#ifdef USE_TCP
                 /* sane IPv4 TCP */ ||
                 (header_ip->version == 4 && pkt_header->caplen >=
                   (offset_to_ip+sizeof(struct iphdr)+sizeof(struct tcphdr)) &&
                   header_ip->protocol == IPPROTO_TCP)
                 /* sane IPv6 TCP */ ||
                 (header_ipv6->version == 6 && pkt_header->caplen >=
                   (offset_to_ip+sizeof(struct ipv6hdr)+sizeof(struct tcphdr)) &&
                   header_ip->protocol == IPPROTO_TCP)
#endif
                 ){
                calltable_element *ce=NULL;
                int idx_rtp=0;
                int save_this_rtp_packet=0;
                int is_rtcp=0;
                uint16_t rtp_port_mask=0xffff;
                struct udphdr *header_udp;
                struct tcphdr *tcph;

                tcph=(tcphdr *)((char*)header_ip+
                    ((header_ip->version == 4) ? sizeof(iphdr) : sizeof(ipv6hdr)));
                header_udp=(udphdr *)((char*)header_ip+
                    ((header_ip->version == 4) ? sizeof(iphdr) : sizeof(ipv6hdr)));
                if (header_ip->protocol == 17) {
                    data=(char *)header_udp+sizeof(*header_udp);
                }else{
                    data=(char *)((unsigned char *)tcph + (tcph->doff * 4));
                }
                datalen=pkt_header->len-((unsigned long)data-(unsigned long)pkt_data);

                if (opt_rtpsave == RTPSAVE_RTP || opt_rtpsave == RTPSAVE_RTPEVENT){
                    save_this_rtp_packet=1;
                }else if (opt_rtpsave==RTPSAVE_RTP_RTCP){
                    save_this_rtp_packet=1;
                    rtp_port_mask=0xfffe;
                    is_rtcp=(htons(header_udp->source) & 1) && (htons(header_udp->dest) & 1);
                }else{
                    save_this_rtp_packet=0;
                }
                if (save_this_rtp_packet
                    && (    ct->find_ip_port_ssrc(
                                hdaddr(header_ip),htons(header_udp->dest) & rtp_port_mask,
                                get_ssrc(data,is_rtcp),
                                &ce, &idx_rtp)
                         || ct->find_ip_port_ssrc(
                                hdaddr(header_ip),htons(header_udp->source) & rtp_port_mask,
                                get_ssrc(data,is_rtcp),
                                &ce, &idx_rtp)
                         || ( opt_do_nat_to && ct->find_ip_port_ssrc(
                                opt_nat_to_addr,htons(header_udp->dest) & rtp_port_mask,
                                get_ssrc(data,is_rtcp),
                                &ce, &idx_rtp))
                         || ( opt_do_nat_to && ct->find_ip_port_ssrc(
                                opt_nat_to_addr,htons(header_udp->source) & rtp_port_mask,
                                get_ssrc(data,is_rtcp),
                                &ce, &idx_rtp))
                       )) {
                    if (ce->f_pcap != NULL && (opt_rtpsave != RTPSAVE_RTPEVENT || data[1] == ce->rtpmap_event)) {
                        ce->last_packet_time=pkt_header->ts.tv_sec;
                        pcap_dump((u_char *)ce->f_pcap, pkt_header, pkt_data);
                        if (opt_packetbuffered) {
                            pcap_dump_flush(ce->f_pcap);
                        }
                    }
                } else if (get_method(data, sip_method, sizeof(sip_method)) ||
                          memcmp(data, "SIP/2.0 ", sizeof("SIP/2.0 "))) {
                    char caller[256] = "";
                    char called[256] = "";
                    char callid[512] = "";

		    data[datalen]=0;
                    if (get_sip_peername(data,datalen,"From:",caller,sizeof(caller))) {
                        get_sip_peername(data,datalen,"f:",caller,sizeof(caller));
                    }
                    if (get_sip_peername(data,datalen,"To:",called,sizeof(called))) {
                        get_sip_peername(data,datalen,"t:",called,sizeof(called));
                    }
		    s=gettag(data,datalen,"Call-ID:",&l) ? :
		      gettag(data,datalen,"i:",&l);
                    memcpy(callid, s, l);
                    callid[l] = '\0';
                    number_filter_matched=false;
                    if ((number_filter.allocated==0) ||
                        (regexec(&number_filter, caller, 1, pmatch, 0)==0) ||
                        (regexec(&number_filter, called, 1, pmatch, 0)==0)) {
                        number_filter_matched=true;
                    }
		    if (s!=NULL && ((idx=ct->find_by_call_id(s,l))<0) && number_filter_matched){
			if ((idx=ct->add(s,l, // callid
                                         caller,
                                         called,
                                         pkt_header->ts.tv_sec))<0){
			    printf("Too many simultaneous calls. Ran out of call table space!\n");
			}else{
			    if (regexec(&method_filter, sip_method, 1, pmatch, 0) == 0){
                                if ((--call_skip_cnt)>0){
                                    if (verbosity>=3){
                                        printf("Skipping %s call from %s to %s \n",sip_method,caller,called);
                                    }
                                    ct->table[idx].f_pcap=NULL;
                                } else {
                                    char fn[1024], dn[1024];
                                    call_skip_cnt = opt_call_skip_n;
                                    expand_dir_template(fn, sizeof(fn), opt_fntemplate,
                                                        caller, called, callid,
                                                        pkt_header->ts.tv_sec);
                                    if (strchr(fn, '/')) {
                                        strcpy(dn, fn);
                                        dirname(dn);
                                        mkdir_p(dn, 0777);
                                    }
                                    ct->table[idx].f_pcap = pcap_dump_open(handle, fn);
                                    strlcpy(ct->table[idx].fn_pcap, fn, sizeof(ct->table[idx].fn_pcap));
                                }
			    }else{
				if (verbosity>=2){
				    printf("Unknown SIP method:'%s'!\n",sip_method);
				}
				ct->table[idx].f_pcap=NULL;
			    }
			}
		    }

                    if(idx>=0){
                        char *sdp = NULL;
                        if (strcmp(sip_method,"BYE")==0){
                            ct->table[idx].had_bye=1;
                        }
                        s=gettag(data,datalen,"Content-Type:",&l) ? :
                          gettag(data,datalen,"c:",&l);
                        if (l > 0 && s && strncasecmp(s, "application/sdp", l) == 0 &&
                                (sdp = strstr(data,"\r\n\r\n")) != NULL) {
                            parse_sdp(sdp, datalen - (sdp - data), &ct->table[idx]);
                        } else if (l > 0 && s && strncasecmp(s, "multipart/mixed;boundary=", MIN(l,25)) == 0 &&
                                (sdp = strstr(data,"\r\n\r\n")) != NULL) {
                            // FIXME: do proper mime miltipart parsing
                            parse_sdp(sdp, datalen - (sdp - data), &ct->table[idx]);
                        }
                        if (ct->table[idx].f_pcap!=NULL){
                            pcap_dump((u_char *)ct->table[idx].f_pcap,pkt_header,pkt_data);
                            if (opt_packetbuffered) {pcap_dump_flush(ct->table[idx].f_pcap);}
                        }
		    }
		}else{
		    if (verbosity>=3){
			char st1[INET6_ADDRSTRLEN];
			char st2[INET6_ADDRSTRLEN];

                        if (header_ip->version == 4){
                            inet_ntop(AF_INET, &(header_ip->saddr), st1, sizeof(st1));
                            inet_ntop(AF_INET, &(header_ip->daddr), st2, sizeof(st2));
                        }else{
                            inet_ntop(AF_INET6, &(header_ipv6->saddr), st1, sizeof(st1));
                            inet_ntop(AF_INET6, &(header_ipv6->daddr), st2, sizeof(st2));
                        }
                        printf ("Skipping udp packet %s:%d->%s:%d\n",
                            st1, htons(header_udp->source),
                            st2, htons(header_udp->dest));
		    }
		}
	    }
	}
    }
    // flush / close files
    ct->do_cleanup(INT32_MAX);
    // close libpcap session
    pcap_close(handle);
    // wait for forked processes;
    {
        int status;
        waitpid(-1, &status, 0);
    }
    return(0);
}

int get_sip_peername(char *data, int data_len, const char *tag, char *peername, int peername_len){
    unsigned long r,r2,peername_tag_len;
    const char *peername_tag = gettag(data,data_len,tag,&peername_tag_len);
    if ((r=(unsigned long)memmem(peername_tag,peername_tag_len,"sip:",4))==0){
	goto fail_exit;
    }
    r+=4;
    if ((r2=(unsigned long)memmem(peername_tag,peername_tag_len,"@",1))==0){
	goto fail_exit;
    }
    if (r2<=r){
	goto fail_exit;
    }
    memcpy(peername,(void*)r,r2-r);
    memset(peername+(r2-r),0,1);
    return 0;
fail_exit:
    strcpy(peername,"empty");
    return 1;
}

int get_ip_port_from_sdp(const char *sdp, size_t sdplen, in_addr_t *addr, unsigned short *port){
    unsigned long l;
    const char *s;
    char s1[20];
    s = gettag(sdp, sdplen, "c=IN IP4 ", &l);
    memset(s1,'\0',sizeof(s1));
    memcpy(s1,s,MIN(l,19));
    if ((long)(*addr=inet_addr(s1))==-1){
	*addr=0;
	*port=0;
	return 1;
    }
    s = gettag(sdp, sdplen, "m=audio ", &l);
    if (l==0){
        s=gettag(sdp, sdplen, "m=image ", &l);
    }
    if (l==0 || (*port=atoi(s))==0){
	*port=0;
	return 1;
    }
    return 0;
}

inline uint32_t get_ssrc (void *udp_packet_data_pointer, bool is_rtcp){
    if (is_rtcp){
        return ntohl(*(uint32_t*)((uint8_t*)udp_packet_data_pointer+4));
    }else{
        return ntohl(*(uint32_t*)((uint8_t*)udp_packet_data_pointer+8));
    }
}

long long parse_size_string(char *s){
    char multiplier[32];
    long long result;
    int i;

    struct multiplier_element {
        char text[32];
        unsigned long value;
    } multipliers[] = {
        {"",1},
        {"b",1},
        {"byte",1},
        {"bytes",1},
        {"kb",1000},
        {"kib",1024},
        {"mb",1000*1000},
        {"mib",1024*1024},
        {"gb",1000*1000*1000},
        {"gib",1024*1024*1024},
        {"",0}
    };

    if (strlen(s)>=32){
        return 0;
    }
    result=0;
    multiplier[0]=0;
    sscanf (s,"%lld%s",&result,multiplier);
    for (i = 0; multipliers[i].value>0; i++){
        if (strcasecmp(multipliers[i].text,multiplier)==0){
            result*=multipliers[i].value;
            return result;
        }
    }
    return 0;
}

#ifndef _GNU_SOURCE
void *memmem(const void* haystack, size_t hl, const void* needle, size_t nl) {
    int i;

    if (nl>hl) return 0;
    for (i=hl-nl+1; i; --i) {
	if (!memcmp(haystack,needle,nl)){
	    return (char*)haystack;
	}
	haystack=(void*)((char*)haystack+1);
    }
    return 0;
}
#endif
