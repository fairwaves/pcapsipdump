#include <string.h>
#include <stdlib.h>
#include "pcapsipdump_strlib.h"

const char * gettag(const char *ptr, unsigned long len, const char *tag, unsigned long *gettaglen){
    unsigned long l, tl;
    const char *r, *lp;

    tl = strlen(tag);
    r = (const char*)memmem(ptr, len, tag, tl);
    if (r == NULL || (ptr != r && r[-1] != '\r' && r[-1] != '\n')) {
        l = 0;
        r = NULL;
    } else {
        r += tl;
        while (r[0] == ' ') {
            r++;
        }
        lp = (const char*)memmem(r, len - (r - ptr), "\r\n", 2);
        if (lp == NULL){
            l = 0;
            r = NULL;
        } else {
            l = lp - r;
        }
    }
    *gettaglen = l;
    return r;
}


uint8_t sdp_get_rtpmap_event(const char *sdp) {
    // a=rtpmap:101 telephone-event/8000
    uint32_t sdp_len = strlen(sdp);
    unsigned long l;
    const char *s;
    const char *te = " telephone-event/";
    int tel = strlen(te);

    s = gettag(sdp, sdp_len, "a=rtpmap:", &l);
    if (s && (strncmp(te, s + 1, tel) == 0 ||
              strncmp(te, s + 2, tel) == 0 ||
              strncmp(te, s + 3, tel) == 0 )) {
        l = atol(s);
        if (l <= 256) {
            return l;
        }
    }
    return 0;
}

