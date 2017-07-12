#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../../pcapsipdump_strlib.h"

const char *p1 = "\
INVITE sip:2001@148.181.138.108;interactionId=0e8e674c-6458-11e2-8d62-db49bc5eef33;serviceId=S1;tenantId=tenant1;routingId=R1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 148.181.168.190;rport;branch=z9hG4bKBX86cmre9gFZH\r\n\
Max-Forwards: 70\r\n\
From: \"\" <sip:null>;tag=BX2g7FKyZZ2NS\r\n\
To: <sip:null@148.181.138.108;interactionId=0e8e674c-6458-11e2-8d62-db49bc5eef33;serviceId=S1;tenantId=tenant1;routingId=R1>\r\n\
Call-ID: e5f1a8f1-defa-1230-b29f-001b7843d1c0\r\n\
CSeq: 39080942 INVITE\r\n\
Contact: <sip:mod_sofia@148.181.168.190:5060>\r\n\
User-Agent: FreeSWITCH-mod_sofia/1.3.0+git~20120923T110355Z~b8e3c1d524\r\n\
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, INFO, UPDATE, REGISTER, REFER, NOTIFY\r\n\
Supported: timer, precondition, path, replaces\r\n\
Allow-Events: talk, hold, conference, refer\r\n\
Content-Type: application/sdp\r\n\
Content-Disposition: session\r\n\
Content-Length: 210\r\n\
X-FS-Support: update_display,send_info\r\n\
Remote-Party-ID: <sip:192131@148.181.168.190>;party=calling;screen=yes;privacy=off\r\n\
\r\n\
v=0\r\n\
o=FreeSWITCH 1358813841 1358813842 IN IP4 148.181.168.190\r\n\
s=FreeSWITCH\r\n\
c=IN IP4 148.181.168.190\r\n\
t=0 0\r\n\
m=audio 20172 RTP/AVP 0 18 101 13\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n\
a=ptime:20\r\n\
";


#define gettag_test_helper(packet, tag, result) \
    s = gettag(packet, strlen(packet), tag, &l); \
    if (strlen(result) == 0) { \
        assert(s == NULL); \
        assert(l == 0); \
    } else { \
        assert(s != NULL); \
        assert(l == strlen(result)); \
        assert(strncmp(s, result, l) == 0); \
    }


void gettag_test() {
    unsigned long l;
    const char *s;
    gettag_test_helper(p1, "Garbage", "");
    gettag_test_helper(p1, "RTP", "");
    gettag_test_helper(p1, "sip:", "");
    gettag_test_helper(p1, "Call-ID:", "e5f1a8f1-defa-1230-b29f-001b7843d1c0");
    gettag_test_helper(p1, "v=", "0");
    gettag_test_helper(p1, "c=IN IP4", "148.181.168.190");
    gettag_test_helper(p1, "a=rtpmap:", "101 telephone-event/8000");
}


void sdp_get_rtpmap_event_test() {
    assert(sdp_get_rtpmap_event("Garbage\r\n") == 0);
    assert(sdp_get_rtpmap_event("a=rtpmap:0 telephone-event/8000\r\n") == 0);
    assert(sdp_get_rtpmap_event("a=rtpmap:1 telephone-event/8000\r\n") == 1);
    assert(sdp_get_rtpmap_event("a=rtpmap:12 telephone-event/8000\r\n") == 12);
    assert(sdp_get_rtpmap_event("a=rtpmap:123 telephone-event/8000\r\n") == 123);
    assert(sdp_get_rtpmap_event("a=rtpmap:333 telephone-event/8000\r\n") == 0);
    assert(sdp_get_rtpmap_event("a=rtpmap:1234 telephone-event/8000\r\n") == 0);
    assert(sdp_get_rtpmap_event(p1) == 101);
}


int main(void) {
    gettag_test();
    sdp_get_rtpmap_event_test();
}
