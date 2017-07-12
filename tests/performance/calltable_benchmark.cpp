#include <string.h>
#include <math.h>
#include <time.h>
#include <pcap.h>

#include "../../calltable.h"

void populate_calltable(calltable *ct, int n_elements){
    for (int i=1; i < n_elements; i++){
        char call_id[32];
        int call_idx;

        sprintf(call_id, "%d", i);
        call_idx = ct->add(call_id, strlen(call_id), 0);
        calltable_element *ce = ct->table;
        for (int j=0; j < calltable_max_ip_per_call; j++){
            ct->add_ip_port(ce, (in_addr_t) i, (unsigned short) i);
            ce += sizeof(calltable_element);
        }
    }
}

float benchmark_find_ip_port_ssrc(calltable *ct, int iterations){
    int idx_leg, idx_rtp;
    clock_t t1;
    t1 = clock();
    for(int i=0;i<iterations;i++){
        ct->find_ip_port_ssrc((in_addr_t)0, 0, 0, &idx_leg, &idx_rtp);
    }
    return((float)(clock()-t1)*1000000.0/(float)(CLOCKS_PER_SEC)/float(iterations));

}

int main(void){
    calltable *ct;

    ct = new calltable;
    populate_calltable(ct,1);
    for(int i=1;i<6;i++){
        int n = int(pow(10,i)/2);
        int m = n - int(pow(10,i-1)/2);
        //printf("populating %d entries...\n", m);
        populate_calltable(ct,m);
        //printf("benchmarking over %d iterations...\n", 3*int(pow(10,5-i)));
        printf("%7.3f us per ct->find_ip_port_ssrc() with %d*%d elements in table\n",
                n,
                benchmark_find_ip_port_ssrc(ct,3*int(pow(10,5-i))),
                calltable_max_ip_per_call);
    }
}
