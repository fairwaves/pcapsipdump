/*
    This file is part of pcapsipdump

    This file is based on linux kernel, namely:
    - udp.h by Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
    - tcp.h by Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
    - ip.h by Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
    - ipv6.h

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

#define PCAPSIPDUMP_VERSION "0.2-trunk"

#define INT32_MAX                (2147483647)

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 * Value to pass to pcap_compile() as the netmask if you don't know what
 * the netmask is.
 */
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

/*** IPv4 */
struct iphdr {
#if defined(__LITTLE_ENDIAN)
	uint8_t	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN)
	uint8_t	version:4,
  		ihl:4;
#else
#error Endian not defined
#endif
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
};

/* IPv6 */
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN)
        uint8_t                 priority:4,
                                version:4;
#elif defined(__BIG_ENDIAN)
        uint8_t                 version:4,
                                priority:4;
#else
#error "__{BIG,LITTLE}_ENDIAN is not defined"
#endif
        uint8_t                 flow_lbl[3];
        uint16_t                payload_len;
        uint8_t                 nexthdr;
        uint8_t                 hop_limit;
        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};

struct udphdr {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len;
	uint16_t	check;
};

struct tcphdr {
        uint16_t  source;
        uint16_t  dest;
        uint32_t  seq;
        uint32_t  ack_seq;
#if defined(__LITTLE_ENDIAN)
        uint16_t   res1:4,
                   doff:4,
                   fin:1,
                   syn:1,
                   rst:1,
                   psh:1,
                   ack:1,
                   urg:1,
                   ece:1,
                   cwr:1;
#elif defined(__BIG_ENDIAN)
        uint16_t   doff:4,
                   res1:4,
                   cwr:1,
                   ece:1,
                   urg:1,
                   ack:1,
                   psh:1,
                   rst:1,
                   syn:1,
                   fin:1;
#else
#error "__{BIG,LITTLE}_ENDIAN is not defined"
#endif
        uint16_t  window;
        uint16_t  check;
        uint16_t  urg_ptr;
};


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
} __attribute__ ((__packed__));
