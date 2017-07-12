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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "trigger.h"
#include "calltable.h"

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#ifdef USE_CALLTABLE_CACHE
using namespace std;

bool operator <(addr_port const& a, addr_port const& b)
{
    return a.addr < b.addr || (a.addr == b.addr && a.port < b.port );
}
#endif

calltable::calltable()
{
    table.clear();
    erase_non_t38 = 0;
    opt_absolute_timeout = INT32_MAX;
}

int calltable::add(
	const char *call_id,
	unsigned long call_id_len,
        const char *caller,
        const char *callee,
	time_t time)
{
    int idx = -1;
    for (int i = 0; i < (int)table.size(); i++) {
	if (table[i].is_used == 0) {
	    idx = i;
	    break;
	}
    }
    if (idx == -1) {
	idx = table.size();
	table.push_back(calltable_element());
    }
    table[idx].is_used=1;
    table[idx].rtpmap_event = 101;
    table[idx].had_t38=0;
    table[idx].had_bye=0;
    memcpy(table[idx].call_id,call_id,MIN(call_id_len,32));
    table[idx].call_id_len=call_id_len;
    memcpy(table[idx].caller, caller, sizeof(table[0].caller));
    memcpy(table[idx].callee, callee, sizeof(table[0].callee));
    table[idx].ip_n=0;
    table[idx].f_pcap=NULL;
    table[idx].first_packet_time = time;
    table[idx].last_packet_time=time;
    global_last_packet_time=time;
#ifdef USE_CALLTABLE_CACHE
    {
        std::string s(call_id, call_id_len);
        call_id_cache[s] = idx;
    }
#endif
    trigger.trigger(&trigger.open,
        table[idx].fn_pcap,
        table[idx].caller,
        table[idx].callee,
        table[idx].call_id,
        table[idx].first_packet_time);
    return idx;
}

int calltable::find_by_call_id(
	const char *call_id,
	unsigned long call_id_len)
{
#ifdef USE_CALLTABLE_CACHE
    std::string s(call_id, call_id_len);
    if (call_id_cache.count(s)){
        return call_id_cache[s];
    }else{
        return -1;
    }
#else
    int i;
    for (i = 0; i < (int)table.size(); i++) {
	if ((table[i].is_used!=0)&&
	    (table[i].call_id_len==call_id_len)&&
	    (memcmp(table[i].call_id,call_id,MIN(call_id_len,32))==0)){
	    return i;
	}
    }
    return -1;
#endif
}

int calltable::add_ip_port(
	    calltable_element *ce,
	    in_addr_t addr,
	    unsigned short port)
{
    if (ce->ip_n >= calltable_max_ip_per_call) {
        return -1;
    }
    for(int i=0; i < ce->ip_n; i++){
        if(ce->ip[i] == addr && ce->port[i] == port) {
            // we already track this ip:port tuple
            return 0;
        }
    }
    ce->ip[ce->ip_n] = addr;
    ce->port[ce->ip_n] = port;
#ifdef USE_CALLTABLE_CACHE
    cache[(struct addr_port){addr, port}] = (struct ce_irtp_ssrc){ce, ce->ip_n, 0};
#endif
    ce->ip_n++;
    return 0;
}

//returns 1 if found or 0 if not found, and updates ce and idx_rtp
int calltable::find_ip_port_ssrc(
            in_addr_t addr,
            unsigned short port,
            uint32_t ssrc,
            calltable_element **ce,
            int *idx_rtp)
{
    int i_leg,i_rtp;

#ifdef USE_CALLTABLE_CACHE
    struct addr_port ap = {addr, port};
    while(true){
        if(this->cache.count(ap)){
            *ce = cache[ap].ce;
            *idx_rtp = cache[ap].irtp;
            if(*ce != NULL){
                if(ssrc != cache[ap].ssrc){ // new ssid
                    if((*ce)->had_bye){ // and call has finished
                        // that's probably ip/port reuse
                        cache.erase(ap);
                        break; // abandon cache code, go to full search
                    }else{
                        //got new ssrc in the same ongoing call - update table & cache
                        (*ce)->ssrc[*idx_rtp] = ssrc;
                        cache[ap] = (struct ce_irtp_ssrc){*ce, *idx_rtp, ssrc};
                    }
                }
                return 1;
            }else{
                return 0;
            }
        }
        break;
    }
#endif
    for (i_leg = 0; i_leg < (int)table.size(); i_leg++){
        for(i_rtp=0; i_rtp < MIN(calltable_max_ip_per_call, table[i_leg].ip_n); i_rtp++){
            if(table[i_leg].port[i_rtp] == port &&
               table[i_leg].ip  [i_rtp] == addr){
                if(!table[i_leg].had_bye || table[i_leg].ssrc[i_rtp]==ssrc){
#ifdef USE_CALLTABLE_CACHE
                    cache[ap] = (struct ce_irtp_ssrc){&table[i_leg], i_rtp, ssrc};
#endif
                    table[i_leg].ssrc[i_rtp]=ssrc;
                    *ce = &table[i_leg];
                    *idx_rtp = i_rtp;
                    return 1;
                }
            }
        }
    }
#ifdef USE_CALLTABLE_CACHE
    // add negative cache entry
    // TODO: how do we clean those up, to avoid memory leak?
    cache[ap] = (struct ce_irtp_ssrc){NULL, -1, 0};
#endif
    return 0;
}

int calltable::do_cleanup( time_t currtime ){
    int idx;
    for (idx = 0; idx < (int)table.size(); idx++) {
	if (table[idx].is_used && (
                    (currtime - table[idx].last_packet_time > 300) ||
                    (currtime - table[idx].first_packet_time > opt_absolute_timeout))){
	    if (table[idx].f_pcap != NULL){
		pcap_dump_close(table[idx].f_pcap);
                if (erase_non_t38 && !table[idx].had_t38) {
                    unlink(table[idx].fn_pcap);
                }else{
                    trigger.trigger(&trigger.close,
                        table[idx].fn_pcap,
                        table[idx].caller,
                        table[idx].callee,
                        table[idx].call_id,
                        table[idx].first_packet_time);
                }
	    }
	    memset((void*)&table[idx],0,sizeof(table[idx]));
	    table[idx].is_used=0;
	    table[idx].ip_n=0;
#ifdef USE_CALLTABLE_CACHE
            for(int i_rtp=0; i_rtp<table[idx].ip_n; i_rtp++){
                struct addr_port ap = {table[idx].ip[i_rtp],
                                       table[idx].port[i_rtp]};
                cache.erase(ap);
            }
            {
                std::string s(table[idx].call_id, table[idx].call_id_len);
                call_id_cache.erase(s);
            }
#endif
	}
    }
    return 0;
}
