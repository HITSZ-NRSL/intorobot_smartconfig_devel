/*
 *  pcap-compatible 802.11 packet sniffer
 *
 *  Copyright (C) 2006-2013 Thomas d'Otreppe
 *  Copyright (C) 2004, 2005 Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>

#ifndef TIOCGWINSZ
#include <sys/termios.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <termios.h>

#include <sys/wait.h>

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "version.h"
#include "pcap.h"
#include "uniqueiv.h"
#include "crypto.h"
#include "osdep/osdep.h"
#include "imlink-dump.h"
#include "osdep/common.h"
#include "common.h"

#ifdef USE_GCRYPT
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

unsigned char en_printinfo = 1;

void reset_term() {
    struct termios oldt,
        newt;
    tcgetattr( STDIN_FILENO, &oldt );
    newt = oldt;
    newt.c_lflag |= ( ICANON | ECHO );
    tcsetattr( STDIN_FILENO, TCSANOW, &newt );
}

void resetSelection()
{
    G.sort_by = SORT_BY_POWER;
    G.sort_inv = 1;

    G.start_print_ap=1;
    G.start_print_sta=1;
    G.selected_ap=1;
    G.selected_sta=1;
    G.selection_ap=0;
    G.selection_sta=0;
    G.mark_cur_ap=0;
    G.skip_columns=0;
    G.do_pause=0;
    G.do_sort_always=0;
    memset(G.selected_bssid, '\x00', 6);
}

int check_shared_key(unsigned char *h80211, int caplen)
{
    int m_bmac, m_smac, m_dmac, n, textlen;
    char ofn[1024];
    char text[4096];
    char prga[4096];
    unsigned int long crc;

    if((unsigned)caplen > sizeof(G.sharedkey[0])) return 1;

    m_bmac = 16;
    m_smac = 10;
    m_dmac = 4;

    if( time(NULL) - G.sk_start > 5)
    {
        /* timeout(5sec) - remove all packets, restart timer */
        memset(G.sharedkey, '\x00', 4096*3);
        G.sk_start = time(NULL);
    }

    /* is auth packet */
    if( (h80211[1] & 0x40) != 0x40 )
    {
        /* not encrypted */
        if( ( h80211[24] + (h80211[25] << 8) ) == 1 )
        {
            /* Shared-Key Authentication */
            if( ( h80211[26] + (h80211[27] << 8) ) == 2 )
            {
                /* sequence == 2 */
                memcpy(G.sharedkey[0], h80211, caplen);
                G.sk_len = caplen-24;
            }
            if( ( h80211[26] + (h80211[27] << 8) ) == 4 )
            {
                /* sequence == 4 */
                memcpy(G.sharedkey[2], h80211, caplen);
            }
        }
        else return 1;
    }
    else
    {
        /* encrypted */
        memcpy(G.sharedkey[1], h80211, caplen);
        G.sk_len2 = caplen-24-4;
    }

    /* check if the 3 packets form a proper authentication */

    if( ( memcmp(G.sharedkey[0]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[1]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[2]+m_bmac, NULL_MAC, 6) == 0 ) ) /* some bssids == zero */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[1]+m_bmac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[2]+m_bmac, 6) != 0 ) ) /* all bssids aren't equal */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[2]+m_smac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[1]+m_dmac, 6) != 0 ) ) /* SA in 2&4 != DA in 3 */
    {
        return 1;
    }

    if( (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[2]+m_dmac, 6) != 0 ) ||
        (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[1]+m_smac, 6) != 0 ) ) /* DA in 2&4 != SA in 3 */
    {
        return 1;
    }

    textlen = G.sk_len;

    if(textlen+4 != G.sk_len2)
    {
        snprintf(G.message, sizeof(G.message), "][ Broken SKA: %02X:%02X:%02X:%02X:%02X:%02X ",
                 *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
                 *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));
        return 1;
    }

    if((unsigned)textlen > sizeof(text) - 4) return 1;

    memcpy(text, G.sharedkey[0]+24, textlen);

    /* increment sequence number from 2 to 3 */
    text[2] = text[2]+1;

    crc = 0xFFFFFFFF;

    for( n = 0; n < textlen; n++ )
        crc = crc_tbl[(crc ^ text[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    /* append crc32 over body */
    text[textlen]     = (crc      ) & 0xFF;
    text[textlen+1]   = (crc >>  8) & 0xFF;
    text[textlen+2]   = (crc >> 16) & 0xFF;
    text[textlen+3]   = (crc >> 24) & 0xFF;

    /* cleartext XOR cipher */
    for(n=0; n<(textlen+4); n++)
    {
        prga[4+n] = (text[n] ^ G.sharedkey[1][28+n]) & 0xFF;
    }

    /* write IV+index */
    prga[0] = G.sharedkey[1][24] & 0xFF;
    prga[1] = G.sharedkey[1][25] & 0xFF;
    prga[2] = G.sharedkey[1][26] & 0xFF;
    prga[3] = G.sharedkey[1][27] & 0xFF;

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf( ofn, sizeof( ofn ) - 1, "%s-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s", G.prefix, G.f_index,
              *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5), "xor" );

    G.f_xor = fopen( ofn, "w");
    if(G.f_xor == NULL)
        return 1;

    for(n=0; n<textlen+8; n++)
        fputc((prga[n] & 0xFF), G.f_xor);

    fflush(G.f_xor);

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf(G.message, sizeof(G.message), "][ %d bytes keystream: %02X:%02X:%02X:%02X:%02X:%02X ",
             textlen+4, *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
             *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));

    memset(G.sharedkey, '\x00', 512*3);
    /* ok, keystream saved */
    return 0;
}

int update_dataps()
{
    struct timeval tv;
    struct AP_info *ap_cur;
    struct NA_info *na_cur;
    int sec, usec, diff, ps;
    float pause;

    gettimeofday(&tv, NULL);

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        sec = (tv.tv_sec - ap_cur->tv.tv_sec);
        usec = (tv.tv_usec - ap_cur->tv.tv_usec);
        pause = (((float)(sec*1000000.0f + usec))/(1000000.0f));
        if( pause > 2.0f )
        {
            diff = ap_cur->nb_data - ap_cur->nb_data_old;
            ps = (int)(((float)diff)/pause);
            ap_cur->nb_dataps = ps;
            ap_cur->nb_data_old = ap_cur->nb_data;
            gettimeofday(&(ap_cur->tv), NULL);
        }
        ap_cur = ap_cur->prev;
    }

    na_cur = G.na_1st;

    while( na_cur != NULL )
    {
        sec = (tv.tv_sec - na_cur->tv.tv_sec);
        usec = (tv.tv_usec - na_cur->tv.tv_usec);
        pause = (((float)(sec*1000000.0f + usec))/(1000000.0f));
        if( pause > 2.0f )
        {
            diff = na_cur->ack - na_cur->ack_old;
            ps = (int)(((float)diff)/pause);
            na_cur->ackps = ps;
            na_cur->ack_old = na_cur->ack;
            gettimeofday(&(na_cur->tv), NULL);
        }
        na_cur = na_cur->next;
    }
    return(0);
}

int list_tail_free(struct pkt_buf **list)
{
    struct pkt_buf **pkts;
    struct pkt_buf *next;

    if(list == NULL) return 1;

    pkts = list;

    while(*pkts != NULL)
    {
        next = (*pkts)->next;
        if( (*pkts)->packet )
        {
            free( (*pkts)->packet);
            (*pkts)->packet=NULL;
        }

        if(*pkts)
        {
            free(*pkts);
            *pkts = NULL;
        }
        *pkts = next;
    }

    *list=NULL;

    return 0;
}

int list_add_packet(struct pkt_buf **list, int length, unsigned char* packet)
{
    struct pkt_buf *next = *list;

    if(length <= 0) return 1;
    if(packet == NULL) return 1;
    if(list == NULL) return 1;

    *list = (struct pkt_buf*) malloc(sizeof(struct pkt_buf));
    if( *list == NULL ) return 1;
    (*list)->packet = (unsigned char*) malloc(length);
    if( (*list)->packet == NULL ) return 1;

    memcpy((*list)->packet,  packet, length);
    (*list)->next = next;
    (*list)->length = length;
    gettimeofday( &((*list)->ctime), NULL);

    return 0;
}

/*
 * Check if the same IV was used if the first two bytes were the same.
 * If they are not identical, it would complain.
 * The reason is that the first two bytes unencrypted are 'aa'
 * so with the same IV it should always be encrypted to the same thing.
 */
int list_check_decloak(struct pkt_buf **list, int length, unsigned char* packet)
{
    struct pkt_buf *next = *list;
    struct timeval tv1;
    int timediff;
    int i, correct;

    if( packet == NULL) return 1;
    if( list == NULL ) return 1;
    if( *list == NULL ) return 1;
    if( length <= 0) return 1;

    gettimeofday(&tv1, NULL);

    timediff = (((tv1.tv_sec - ((*list)->ctime.tv_sec)) * 1000000) + (tv1.tv_usec - ((*list)->ctime.tv_usec))) / 1000;
    if( timediff > BUFFER_TIME )
    {
        list_tail_free(list);
        next=NULL;
    }

    while(next != NULL)
    {
        if(next->next != NULL)
        {
            timediff = (((tv1.tv_sec - (next->next->ctime.tv_sec)) * 1000000) + (tv1.tv_usec - (next->next->ctime.tv_usec))) / 1000;
            if( timediff > BUFFER_TIME )
            {
                list_tail_free(&(next->next));
                break;
            }
        }
        if( (next->length + 4) == length)
        {
            correct = 1;
            // check for 4 bytes added after the end
            for(i=28;i<length-28;i++)   //check everything (in the old packet) after the IV (including crc32 at the end)
            {
                if(next->packet[i] != packet[i])
                {
                    correct = 0;
                    break;
                }
            }
            if(!correct)
            {
                correct = 1;
                // check for 4 bytes added at the beginning
                for(i=28;i<length-28;i++)   //check everything (in the old packet) after the IV (including crc32 at the end)
                {
                    if(next->packet[i] != packet[4+i])
                    {
                        correct = 0;
                        break;
                    }
                }
            }
            if(correct == 1)
                return 0;   //found decloaking!
        }
        next = next->next;
    }

    return 1; //didn't find decloak
}

int remove_namac(unsigned char* mac)
{
    struct NA_info *na_cur = NULL;
    struct NA_info *na_prv = NULL;

    if(mac == NULL)
        return( -1 );

    na_cur = G.na_1st;
    na_prv = NULL;

    while( na_cur != NULL )
    {
        if( ! memcmp( na_cur->namac, mac, 6 ) )
            break;

        na_prv = na_cur;
        na_cur = na_cur->next;
    }

    /* if it's known, remove it */
    if( na_cur != NULL )
    {
        /* first in linked list */
        if(na_cur == G.na_1st)
        {
            G.na_1st = na_cur->next;
        }
        else
        {
            na_prv->next = na_cur->next;
        }
        free(na_cur);
        na_cur=NULL;
    }

    return( 0 );
}

int dump_add_packet( unsigned char *h80211, int caplen, struct rx_info *ri, int cardnum )
{
    int i, n, seq, offset;
    unsigned z;
    int type, length, numuni=0, numauth=0;
    unsigned char *p, *org_p;
    unsigned char bssid[6];
    unsigned char stmac[6];
    unsigned char namac[6];

    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    // struct NA_info *na_cur = NULL;
    struct AP_info *ap_prv = NULL;
    struct ST_info *st_prv = NULL;
    //struct NA_info *na_prv = NULL;

    /* skip all non probe response frames in active scanning simulation mode */
    if( G.active_scan_sim > 0 && h80211[0] != 0x50 )
        return(0);

    /* skip packets smaller than a 802.11 header */

    if( caplen < 24 )
        goto write_packet;

    /* skip (uninteresting) control frames */

    if( ( h80211[0] & 0x0C ) == 0x04 )
        goto write_packet;

    /* if it's a LLC null packet, just forget it (may change in the future) */

    if ( caplen > 28)
        if ( memcmp(h80211 + 24, llcnull, 4) == 0)
            return ( 0 );

    /* grab the sequence number */
    seq = ((h80211[22]>>4)+(h80211[23]<<4));

    /* locate the access point's MAC address */

    switch( h80211[1] & 3 )
    {
        case  0: memcpy( bssid, h80211 + 16, 6 ); break;  //Adhoc
        case  1: memcpy( bssid, h80211 +  4, 6 ); break;  //ToDS
        case  2: memcpy( bssid, h80211 + 10, 6 ); break;  //FromDS
        case  3: memcpy( bssid, h80211 + 10, 6 ); return;  //WDS -> Transmitter taken as BSSID
    }
    
   
    /* update our chained list of access points */

    ap_cur = G.ap_1st;
    ap_prv = NULL;

    while( ap_cur != NULL )
    {
        if( ! memcmp( ap_cur->bssid, bssid, 6 ) )
            break;

        ap_prv = ap_cur;
        ap_cur = ap_cur->next;
    }

    /* if it's a new access point, add it */

    if( ap_cur == NULL )
    {
        if( ! ( ap_cur = (struct AP_info *) malloc(
                    sizeof( struct AP_info ) ) ) )
        {
            perror( "malloc failed" );
            return( 1 );
        }

        /* if mac is listed as unknown, remove it */
        remove_namac(bssid);

        memset( ap_cur, 0, sizeof( struct AP_info ) );

        if( G.ap_1st == NULL )
            G.ap_1st = ap_cur;
        else
            ap_prv->next  = ap_cur;

        memcpy( ap_cur->bssid, bssid, 6 );

        ap_cur->prev = ap_prv;

        ap_cur->tinit = time( NULL );
        ap_cur->tlast = time( NULL );

        ap_cur->avg_power   = -1;
        ap_cur->best_power  = -1;
        ap_cur->power_index = -1;

        for( i = 0; i < NB_PWR; i++ )
            ap_cur->power_lvl[i] = -1;

        ap_cur->channel    = -1;
        ap_cur->max_speed  = -1;
        ap_cur->security   = 0;

        ap_cur->uiv_root = uniqueiv_init();

        ap_cur->nb_dataps = 0;
        ap_cur->nb_data_old = 0;
        gettimeofday(&(ap_cur->tv), NULL);

        ap_cur->dict_started = 0;

        ap_cur->key = NULL;

        G.ap_end = ap_cur;

        ap_cur->nb_bcn     = 0;

        ap_cur->rx_quality = 0;
        ap_cur->fcapt      = 0;
        ap_cur->fmiss      = 0;
        ap_cur->last_seq   = 0;
        gettimeofday( &(ap_cur->ftimef), NULL);
        gettimeofday( &(ap_cur->ftimel), NULL);
        gettimeofday( &(ap_cur->ftimer), NULL);

        ap_cur->ssid_length = 0;
        ap_cur->essid_stored = 0;
        ap_cur->timestamp = 0;

        ap_cur->decloak_detect=G.decloak;
        ap_cur->is_decloak = 0;
        ap_cur->packets = NULL;

        ap_cur->marked = 0;
        ap_cur->marked_color = 1;

        ap_cur->data_root = NULL;
        ap_cur->EAP_detected = 0;
        memcpy(ap_cur->gps_loc_min, G.gps_loc, sizeof(float)*5);
        memcpy(ap_cur->gps_loc_max, G.gps_loc, sizeof(float)*5);
        memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float)*5);
    }

    /* update the last time seen */

    ap_cur->tlast = time( NULL );

    /* only update power if packets comes from
     * the AP: either type == mgmt and SA != BSSID,
     * or FromDS == 1 and ToDS == 0 */

    if( ( ( h80211[1] & 3 ) == 0 &&
          memcmp( h80211 + 10, bssid, 6 ) == 0 ) ||
        ( ( h80211[1] & 3 ) == 2 ) )
    {
        ap_cur->power_index = ( ap_cur->power_index + 1 ) % NB_PWR;
        ap_cur->power_lvl[ap_cur->power_index] = ri->ri_power;

        ap_cur->avg_power = 0;

        for( i = 0, n = 0; i < NB_PWR; i++ )
        {
            if( ap_cur->power_lvl[i] != -1 )
            {
                ap_cur->avg_power += ap_cur->power_lvl[i];
                n++;
            }
        }

        if( n > 0 )
        {
            ap_cur->avg_power /= n;
            if( ap_cur->avg_power > ap_cur->best_power )
            {
                ap_cur->best_power = ap_cur->avg_power;
                memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float)*5);
            }
        }
        else
            ap_cur->avg_power = -1;

        /* every packet in here comes from the AP */

        if(G.gps_loc[0] > ap_cur->gps_loc_max[0])
            ap_cur->gps_loc_max[0] = G.gps_loc[0];
        if(G.gps_loc[1] > ap_cur->gps_loc_max[1])
            ap_cur->gps_loc_max[1] = G.gps_loc[1];
        if(G.gps_loc[2] > ap_cur->gps_loc_max[2])
            ap_cur->gps_loc_max[2] = G.gps_loc[2];

        if(G.gps_loc[0] < ap_cur->gps_loc_min[0])
            ap_cur->gps_loc_min[0] = G.gps_loc[0];
        if(G.gps_loc[1] < ap_cur->gps_loc_min[1])
            ap_cur->gps_loc_min[1] = G.gps_loc[1];
        if(G.gps_loc[2] < ap_cur->gps_loc_min[2])
            ap_cur->gps_loc_min[2] = G.gps_loc[2];
//        printf("seqnum: %i\n", seq);

        if(ap_cur->fcapt == 0 && ap_cur->fmiss == 0) gettimeofday( &(ap_cur->ftimef), NULL);
        if(ap_cur->last_seq != 0) ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
        ap_cur->last_seq = seq;
        ap_cur->fcapt++;
        gettimeofday( &(ap_cur->ftimel), NULL);

//         if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
    }

    if( h80211[0] == 0x80 )
    {
        ap_cur->nb_bcn++;
    }

    ap_cur->nb_pkt++;

    /* find wpa handshake */
    if( h80211[0] == 0x10 )
    {
        /* reset the WPA handshake state */

        if( st_cur != NULL && st_cur->wpa.state != 0xFF )
            st_cur->wpa.state = 0;
//        printf("initial auth %d\n", ap_cur->wpa_state);
    }

    /* locate the station MAC in the 802.11 header */

    switch( h80211[1] & 3 )
    {
        case  0:

            /* if management, check that SA != BSSID */

            if( memcmp( h80211 + 10, bssid, 6 ) == 0 )
                goto skip_station;

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  1:

            /* ToDS packet, must come from a client */

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  2:

            /* FromDS packet, reject broadcast MACs */

            if( (h80211[4]%2) != 0 ) goto skip_station;
            memcpy( stmac, h80211 +  4, 6 ); break;

        default: goto skip_station;
    }

  skip_station:
    /* packet parsing: Beacon or Probe Response */

    if( h80211[0] == 0x80 || h80211[0] == 0x50 )
    {
        if( !(ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) )
        {
            if( ( h80211[34] & 0x10 ) >> 4 ) ap_cur->security |= STD_WEP|ENC_WEP;
            else ap_cur->security |= STD_OPN;
        }

        ap_cur->preamble = ( h80211[34] & 0x20 ) >> 5;

        unsigned long long *tstamp = (unsigned long long *) (h80211 + 24);
        ap_cur->timestamp = letoh64(*tstamp);

        p = h80211 + 36;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            //only update the essid length if the new length is > the old one
            if( p[0] == 0x00 && (ap_cur->ssid_length < p[1]) ) ap_cur->ssid_length = p[1];

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                /* found a non-cloaked ESSID */

//                n = ( p[1] > 32 ) ? 32 : p[1];
                n = p[1];

                memset( ap_cur->essid, 0, 256 );
                memcpy( ap_cur->essid, p + 2, n );

                for( i = 0; i < n; i++ )
                    if( ( ap_cur->essid[i] >   0 && ap_cur->essid[i] <  32 ) ||
                        ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                        ap_cur->essid[i] = '.';
            }

            /* get the maximum speed in Mb and the AP's channel */

            if( p[0] == 0x01 || p[0] == 0x32 )
            {
                if(ap_cur->max_speed < ( p[1 + p[1]] & 0x7F ) / 2)
                    ap_cur->max_speed = ( p[1 + p[1]] & 0x7F ) / 2;
            }

            if( p[0] == 0x03 )
                ap_cur->channel = p[2];

            p += 2 + p[1];
        }
    }

    /* packet parsing: Beacon & Probe response */

    if( (h80211[0] == 0x80 || h80211[0] == 0x50) && caplen > 38)
    {
        p=h80211+36;         //ignore hdr + fixed params

        while( p < h80211 + caplen )
        {
            type = p[0];
            length = p[1];
            if(p+2+length > h80211 + caplen) {
/*                printf("error parsing tags! %p vs. %p (tag: %i, length: %i,position: %i)\n", (p+2+length), (h80211+caplen), type, length, (p-h80211));
                  exit(1);*/
                break;
            }

            if( (type == 0xDD && (length >= 8) && (memcmp(p+2, "\x00\x50\xF2\x01\x01\x00", 6) == 0)) || (type == 0x30) )
            {
                ap_cur->security &= ~(STD_WEP|ENC_WEP|STD_WPA);

                org_p = p;
                offset = 0;

                if(type == 0xDD)
                {
                    //WPA defined in vendor specific tag -> WPA1 support
                    ap_cur->security |= STD_WPA;
                    offset = 4;
                }

                if(type == 0x30)
                {
                    ap_cur->security |= STD_WPA2;
                    offset = 0;
                }

                if(length < (18+offset))
                {
                    p += length+2;
                    continue;
                }

                if( p+9+offset > h80211+caplen )
                    break;
                numuni  = p[8+offset] + (p[9+offset]<<8);

                if( p+ (11+offset) + 4*numuni > h80211+caplen)
                    break;
                numauth = p[(10+offset) + 4*numuni] + (p[(11+offset) + 4*numuni]<<8);

                p += (10+offset);

                if(type != 0x30)
                {
                    if( p + (4*numuni) + (2+4*numauth) > h80211+caplen)
                        break;
                }
                else
                {
                    if( p + (4*numuni) + (2+4*numauth) + 2 > h80211+caplen)
                        break;
                }

                for(i=0; i<numuni; i++)
                {
                    switch(p[i*4+3])
                    {
                        case 0x01:
                            ap_cur->security |= ENC_WEP;
                            break;
                        case 0x02:
                            ap_cur->security |= ENC_TKIP;
                            break;
                        case 0x03:
                            ap_cur->security |= ENC_WRAP;
                            break;
                        case 0x04:
                            ap_cur->security |= ENC_CCMP;
                            break;
                        case 0x05:
                            ap_cur->security |= ENC_WEP104;
                            break;
                        default:
                            break;
                    }
                }

                p += 2+4*numuni;

                for(i=0; i<numauth; i++)
                {
                    switch(p[i*4+3])
                    {
                        case 0x01:
                            ap_cur->security |= AUTH_MGT;
                            break;
                        case 0x02:
                            ap_cur->security |= AUTH_PSK;
                            break;
                        default:
                            break;
                    }
                }

                p += 2+4*numauth;

                if( type == 0x30 ) p += 2;

                p = org_p + length+2;
            }
            else if( (type == 0xDD && (length >= 8) && (memcmp(p+2, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
            {
                ap_cur->security |= STD_QOS;
                p += length+2;
            }
            else p += length+2;
        }
    }

    /* packet parsing: Authentication Response */

    if( h80211[0] == 0xB0 && caplen >= 30)
    {
        if( ap_cur->security & STD_WEP )
        {
            //successful step 2 or 4 (coming from the AP)
            if(memcmp(h80211+28, "\x00\x00", 2) == 0 &&
               (h80211[26] == 0x02 || h80211[26] == 0x04))
            {
                ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
                if(h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
                if(h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
            }
        }
    }

    /* packet parsing: Association Request */

    if( h80211[0] == 0x00 && caplen > 28 )
    {
        p = h80211 + 28;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                /* found a non-cloaked ESSID */

                n = ( p[1] > 32 ) ? 32 : p[1];

                memset( ap_cur->essid, 0, 33 );
                memcpy( ap_cur->essid, p + 2, n );

                for( i = 0; i < n; i++ )
                    if( ap_cur->essid[i] < 32 ||
                        ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                        ap_cur->essid[i] = '.';
            }

            p += 2 + p[1];
        }
        if(st_cur != NULL)
            st_cur->wpa.state = 0;
    }

    /* packet parsing: some data */

    if( ( h80211[0] & 0x0C ) == 0x08 )
    {
        /* update the channel if we didn't get any beacon */

        if( ap_cur->channel == -1 )
        {
            if(ri->ri_channel > 0 && ri->ri_channel < 167)
                ap_cur->channel = ri->ri_channel;
            else
                ap_cur->channel = G.channel[cardnum];
        }

        /* check the SNAP header to see if data is encrypted */

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        /* Check if 802.11e (QoS) */
        if( (h80211[0] & 0x80) == 0x80)
        {
            z+=2;
            if(st_cur != NULL)
            {
                if( (h80211[1] & 3) == 1 ) //ToDS
                    st_cur->qos_to_ds = 1;
                else
                    st_cur->qos_fr_ds = 1;
            }
        }
        else
        {
            if(st_cur != NULL)
            {
                if( (h80211[1] & 3) == 1 ) //ToDS
                    st_cur->qos_to_ds = 0;
                else
                    st_cur->qos_fr_ds = 0;
            }
        }

        if(z==24)
        {
            if(list_check_decloak(&(ap_cur->packets), caplen, h80211) != 0)
            {
                list_add_packet(&(ap_cur->packets), caplen, h80211);
            }
            else
            {
                ap_cur->is_decloak = 1;
                ap_cur->decloak_detect = 0;
                list_tail_free(&(ap_cur->packets));
                memset(G.message, '\x00', sizeof(G.message));
                snprintf( G.message, sizeof( G.message ) - 1,
                          "][ Decloak: %02X:%02X:%02X:%02X:%02X:%02X ",
                          ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2],
                          ap_cur->bssid[3], ap_cur->bssid[4], ap_cur->bssid[5]);
            }
        }

        if( z + 26 > (unsigned)caplen )
            goto write_packet;

        if( h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03 )
        {
//            if( ap_cur->encryption < 0 )
//                ap_cur->encryption = 0;

            /* if ethertype == IPv4, find the LAN address */

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00 &&
                ( h80211[1] & 3 ) == 0x01 )
                memcpy( ap_cur->lanip, &h80211[z + 20], 4 );

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06 )
                memcpy( ap_cur->lanip, &h80211[z + 22], 4 );
        }
//        else
//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5 );


        if(ap_cur->security == 0 || (ap_cur->security & STD_WEP) )
        {
            if( (h80211[1] & 0x40) != 0x40 )
            {
                ap_cur->security |= STD_OPN;
            }
            else
            {
                if((h80211[z+3] & 0x20) == 0x20)
                {
                    ap_cur->security |= STD_WPA;
                }
                else
                {
                    ap_cur->security |= STD_WEP;
                    if( (h80211[z+3] & 0xC0) != 0x00)
                    {
                        ap_cur->security |= ENC_WEP40;
                    }
                    else
                    {
                        ap_cur->security &= ~ENC_WEP40;
                        ap_cur->security |= ENC_WEP;
                    }
                }
            }
        }

        if( z + 10 > (unsigned)caplen )
            goto write_packet;

        if( ap_cur->security & STD_WEP )
        {
            /* WEP: check if we've already seen this IV */

            if( ! uniqueiv_check( ap_cur->uiv_root, &h80211[z] ) )
            {
                /* first time seen IVs */

                uniqueiv_mark( ap_cur->uiv_root, &h80211[z] );

                ap_cur->nb_data++;
            }

            // Record all data linked to IV to detect WEP Cloaking
            if( G.f_ivs == NULL && G.detect_anomaly)
            {
                // Only allocate this when seeing WEP AP
                if (ap_cur->data_root == NULL)
                    ap_cur->data_root = data_init();

                // Only works with full capture, not IV-only captures
                if (data_check(ap_cur->data_root, &h80211[z], &h80211[z + 4])
                    == CLOAKING && ap_cur->EAP_detected == 0)
                {

                    //If no EAP/EAP was detected, indicate WEP cloaking
                    memset(G.message, '\x00', sizeof(G.message));
                    snprintf( G.message, sizeof( G.message ) - 1,
                              "][ WEP Cloaking: %02X:%02X:%02X:%02X:%02X:%02X ",
                              ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2],
                              ap_cur->bssid[3], ap_cur->bssid[4], ap_cur->bssid[5]);

                }
            }

        }
        else
        {
            ap_cur->nb_data++;
        }

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        /* Check if 802.11e (QoS) */
        if( (h80211[0] & 0x80) == 0x80) z+=2;

        if( z + 26 > (unsigned)caplen )
            goto write_packet;

        z += 6;     //skip LLC header

        /* check ethertype == EAPOL */
        if( h80211[z] == 0x88 && h80211[z + 1] == 0x8E && (h80211[1] & 0x40) != 0x40 )
        {
            ap_cur->EAP_detected = 1;

            z += 2;     //skip ethertype

            if( st_cur == NULL )
                goto write_packet;

            /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) == 0 &&
                ( h80211[z + 6] & 0x80 ) != 0 &&
                ( h80211[z + 5] & 0x01 ) == 0 )
            {
                memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                st_cur->wpa.state = 1;
            }


            /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

            if( z+17+32 > (unsigned)caplen )
                goto write_packet;

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) == 0 &&
                ( h80211[z + 6] & 0x80 ) == 0 &&
                ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );
                    st_cur->wpa.state |= 2;

                }

                if( (st_cur->wpa.state & 4) != 4 )
                {
                    st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
                        +   h80211[z + 3] + 4;

                    if (caplen - z < st_cur->wpa.eapol_size || st_cur->wpa.eapol_size == 0 ||
                        caplen - z < 81 + 16 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
                    {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = h80211[z + 6] & 7;
                }
            }

            /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) != 0 &&
                ( h80211[z + 6] & 0x80 ) != 0 &&
                ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                    st_cur->wpa.state |= 1;
                }

                if( (st_cur->wpa.state & 4) != 4 )
                {
                    st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
                        +   h80211[z + 3] + 4;

                    if (caplen - (unsigned)z < st_cur->wpa.eapol_size || st_cur->wpa.eapol_size == 0 ||
                        caplen - (unsigned)z < 81 + 16 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
                    {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = h80211[z + 6] & 7;
                }
            }

            if( st_cur->wpa.state == 7)
            {
                memcpy( st_cur->wpa.stmac, st_cur->stmac, 6 );
                memcpy( G.wpa_bssid, ap_cur->bssid, 6 );
                memset(G.message, '\x00', sizeof(G.message));
                snprintf( G.message, sizeof( G.message ) - 1,
                          "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
                          G.wpa_bssid[0], G.wpa_bssid[1], G.wpa_bssid[2],
                          G.wpa_bssid[3], G.wpa_bssid[4], G.wpa_bssid[5]);


            }
        }
    }


  write_packet:

    if(ap_cur != NULL)
    {
        if( h80211[0] == 0x80 && G.one_beacon){
            if( !ap_cur->beacon_logged )
                ap_cur->beacon_logged = 1;
            else return ( 0 );
        }
    }

    if(G.record_data)
    {
        if( ( (h80211[0] & 0x0C) == 0x00 ) && ( (h80211[0] & 0xF0) == 0xB0 ) )
        {
            /* authentication packet */
            check_shared_key(h80211, caplen);
        }
    }

    if(ap_cur != NULL)
    {
        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            return(1);
        }

    }

    /* this changes the local ap_cur, st_cur and na_cur variables and should be the last check befor the actual write */
    if(caplen < 24 && caplen >= 10 && h80211[0])
    {
        /* RTS || CTS || ACK || CF-END || CF-END&CF-ACK*/
        //(h80211[0] == 0xB4 || h80211[0] == 0xC4 || h80211[0] == 0xD4 || h80211[0] == 0xE4 || h80211[0] == 0xF4)

        /* use general control frame detection, as the structure is always the same: mac(s) starting at [4] */
        if(h80211[0] & 0x04)
        {
            p=h80211+4;
            while(p <= h80211+16 && p<=h80211+caplen)
            {
                memcpy(namac, p, 6);

                if(memcmp(namac, NULL_MAC, 6) == 0)
                {
                    p+=6;
                    continue;
                }

                if(memcmp(namac, BROADCAST, 6) == 0)
                {
                    p+=6;
                    continue;
                }

                if(G.hide_known)
                {
                    /* check AP list */
                    ap_cur = G.ap_1st;
                    ap_prv = NULL;

                    while( ap_cur != NULL )
                    {
                        if( ! memcmp( ap_cur->bssid, namac, 6 ) )
                            break;

                        ap_prv = ap_cur;
                        ap_cur = ap_cur->next;
                    }

                    /* if it's an AP, try next mac */

                    if( ap_cur != NULL )
                    {
                        p+=6;
                        continue;
                    }

                    /* check ST list */
                    st_cur = G.st_1st;
                    st_prv = NULL;

                    while( st_cur != NULL )
                    {
                        if( ! memcmp( st_cur->stmac, namac, 6 ) )
                            break;

                        st_prv = st_cur;
                        st_cur = st_cur->next;
                    }

                    /* if it's a client, try next mac */

                    if( st_cur != NULL )
                    {
                        p+=6;
                        continue;
                    }
                }

                /*grab next mac (for rts frames)*/
                p+=6;
            }
        }
    }

    return( 0 );
}

void sighandler( int signum)
{
    signal( signum, sighandler );

    if( signum == SIGINT || signum == SIGTERM )
    {
        reset_term();
        alarm( 1 );
        G.do_exit = 1;
        signal( SIGALRM, sighandler );
        dprintf( STDOUT_FILENO, "\n" );
    }

    if( signum == SIGSEGV )
    {
        fprintf( stderr, "Caught signal 11 (SIGSEGV). Please"
                 " contact the author!\33[?25h\n\n" );
        fflush( stdout );
        exit( 1 );
    }

    if( signum == SIGALRM )
    {
        dprintf( STDERR_FILENO, "Caught signal 14 (SIGALRM). Please"
                 " contact the author!\33[?25h\n\n" );
        _exit( 1 );
    }

    if( signum == SIGCHLD )
        wait( NULL );

    if( signum == SIGWINCH )
    {
        fprintf( stderr, "\33[2J" );
        fflush( stdout );
    }
}

int send_probe_request(struct wif *wi)
{
    int len;
    unsigned char p[4096], r_smac[6];

    memcpy(p, PROBE_REQ, 24);

    len = 24;

    p[24] = 0x00;      //ESSID Tag Number
    p[25] = 0x00;      //ESSID Tag Length

    len += 2;

    memcpy(p+len, RATES, 16);

    len += 16;

    r_smac[0] = 0x00;
    r_smac[1] = rand() & 0xFF;
    r_smac[2] = rand() & 0xFF;
    r_smac[3] = rand() & 0xFF;
    r_smac[4] = rand() & 0xFF;
    r_smac[5] = rand() & 0xFF;

    memcpy(p+10, r_smac, 6);

    if (wi_write(wi, p, len, NULL) == -1) {
        switch (errno) {
            case EAGAIN:
            case ENOBUFS:
                usleep(10000);
                return 0; /* XXX not sure I like this... -sorbo */
        }

        perror("wi_write()");
        return -1;
    }

    return 0;
}

int send_probe_requests(struct wif *wi[], int cards)
{
    int i=0;
    for(i=0; i<cards; i++)
    {
        send_probe_request(wi[i]);
    }
    return 0;
}

int getchancount(int valid)
{
    int i=0, chan_count=0;

    while(G.channels[i])
    {
        i++;
        if(G.channels[i] != -1)
            chan_count++;
    }

    if(valid) return chan_count;
    return i;
}

int setup_card(char *iface, struct wif **wis)
{
    struct wif *wi;

    wi = wi_open(iface);
    if (!wi)
        return -1;
    *wis = wi;

    return 0;
}

int init_cards(const char* cardstr, char *iface[], struct wif **wi)
{
    char *buffer;
    char *buf;
    int if_count=0;
    int i=0, again=0;

    buf = buffer = (char*) malloc( sizeof(char) * 1025 );
    strncpy( buffer, cardstr, 1025 );
    buffer[1024] = '\0';

    while( ((iface[if_count]=strsep(&buffer, ",")) != NULL) && (if_count < MAX_CARDS) )
    {
        again=0;
        for(i=0; i<if_count; i++)
        {
            if(strcmp(iface[i], iface[if_count]) == 0)
                again=1;
        }
        if(again) continue;
        if(setup_card(iface[if_count], &(wi[if_count])) != 0)
        {
            free(buf);
            return -1;
        }
        if_count++;
    }

    free(buf);
    return if_count;
}

int check_monitor(struct wif *wi[], int *fd_raw, int *fdh, int cards)
{
    int i, monitor;
    char ifname[64];

    for(i=0; i<cards; i++)
    {
        monitor = wi_get_monitor(wi[i]);
        if(monitor != 0)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ %s reset to monitor mode", wi_get_ifname(wi[i]));
            //reopen in monitor mode

            strncpy(ifname, wi_get_ifname(wi[i]), sizeof(ifname)-1);
            ifname[sizeof(ifname)-1] = 0;

            wi_close(wi[i]);
            wi[i] = wi_open(ifname);
            if (!wi[i]) {
                printf("Can't reopen %s\n", ifname);
                exit(1);
            }

            fd_raw[i] = wi_fd(wi[i]);
            if (fd_raw[i] > *fdh)
                *fdh = fd_raw[i];
        }
    }
    return 0;
}

int check_channel(struct wif *wi[], int cards)
{
    int i, chan;
    for(i=0; i<cards; i++)
    {
        chan = wi_get_channel(wi[i]);
        if(G.ignore_negative_one == 1 && chan==-1) return 0;
        if(G.channel[i] != chan)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ fixed channel %s: %d ", wi_get_ifname(wi[i]), chan);
            wi_set_channel(wi[i], G.channel[i]);
        }
    }
    return 0;
}

int check_frequency(struct wif *wi[], int cards)
{
    int i, freq;
    for(i=0; i<cards; i++)
    {
        freq = wi_get_freq(wi[i]);
        if(freq < 0) continue;
        if(G.frequency[i] != freq)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ fixed frequency %s: %d ", wi_get_ifname(wi[i]), freq);
            wi_set_freq(wi[i], G.frequency[i]);
        }
    }
    return 0;
}

//clean aps with same names
void clean_aps()
{
    int i;
    char essid[50];  //can be a bug here
    char essid_array[50]; //max ap number 
    char power_array[50]; //max ap number 
    int  essid_index=0;
    char enc[10];
    char auth[10];
    char securitystr[23];

    int Rssi_Quality;
    struct AP_info *ap_cur;
    int idx;

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        /* skip APs with only one packet, or those older than 2 min.
         * always skip if bssid == broadcast */
        if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
            memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->prev;
            continue;
        }
        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }
        if(ap_cur->ssid_length <= 0 || ap_cur->essid == NULL)
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        /*SSID*/
        if(ap_cur->ssid_length > 30)
        {
            sprintf(essid, "0x");
            for (idx = 0; (idx < 30) && (idx < ap_cur->ssid_length); idx++)
                sprintf(essid + 2 + (idx*2), "%02X", ap_cur->essid[idx]);
        }
        else
            strcpy(essid, ap_cur->essid);

        if(essid_index >= 50)
            break;

        for(i=0; i<essid_index; i++)
        {
            if(strcmp(essid, essid_array[i])) 
	    {
               if (ap_cur->avg_power >= power_array[i] )
                {
                    power_array[i] = ap_cur->avg_power;
                } 
            }	
        }

        ap_cur = ap_cur->prev;
    }
}
//get essid corresponding to bssid
void iwscan_print_aplist()
{
    char essid[50];  //can be a bug here
    char essid_array[50]; //max ap number 
    int  essid_index=0;
    char enc[10];
    char auth[10];
    char securitystr[23];

    int Rssi_Quality;
    struct AP_info *ap_cur;
    char *msg;
    int totallen, idx;

    totallen = 5000;
    msg = (char *) malloc(sizeof(char) * totallen);
    memset(msg, 0 , totallen);
    sprintf(msg,"%s","\n");
    sprintf(msg+strlen(msg),"%-4s%-33s%-23s%-23s%-9s\n",
            "Ch", "SSID", "BSSID", "Security", "Siganl(%)");

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        /* skip APs with only one packet, or those older than 2 min.
         * always skip if bssid == broadcast */
        if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
            memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->prev;
            continue;
        }
        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }
        switch(ap_cur->security & 0x000f)
        {
            case 0x0001:
                strcpy(enc,"NONE");
                break;
            case 0x0002:
                strcpy(enc,"WEP");
                break;
            case 0x0004:
                strcpy(enc,"WPA");
                break;
            case 0x0008:
                strcpy(enc, "WPA2");
                break;
            case 0x000C:
                strcpy(enc, "WPAWPA2");
        }

        switch(ap_cur->security & 0x0f00)
        {
            case 0x0200:
                strcpy(auth, "NONE");
                break;
            case 0x0400:
                strcpy(auth, "PSK");
                break;
            case 0x0800:
                strcpy(auth, "MGT");
            default:
                strcpy(auth, "NONE");
        }

        if(ap_cur->ssid_length <= 0 || ap_cur->essid == NULL)
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        /*SSID*/
        if(ap_cur->ssid_length > 30)
        {
            sprintf(essid, "0x");
            for (idx = 0; (idx < 30) && (idx < ap_cur->ssid_length); idx++)
                sprintf(essid + 2 + (idx*2), "%02X", ap_cur->essid[idx]);
        }
        else
            strcpy(essid, ap_cur->essid);

        /*Security*/
        if(!strcmp(enc, "NONE"))
            sprintf(securitystr, "NONE");
        else if(!strcmp(enc, "WEP"))
            sprintf(securitystr, "WEP");
        else
            sprintf(securitystr, "%s/%s", auth, enc);

        /* Rssi*/
        if (ap_cur->avg_power >= -50)
            Rssi_Quality = 100;
        else if (ap_cur->avg_power >= -80)    /* between -50 ~ -80dbm*/
            Rssi_Quality = (int)(24 + ((ap_cur->avg_power + 80) * 26)/10);
        else if (ap_cur->avg_power >= -90)   /* between -80 ~ -90dbm*/
            Rssi_Quality = (int)(((ap_cur->avg_power + 90) * 26)/10);
        else    /* < -84 dbm*/
            Rssi_Quality = 0;

        sprintf(msg+strlen(msg),"%-4d,", ap_cur->channel);
        sprintf(msg+strlen(msg),"%-33s,", essid);
        sprintf(msg+strlen(msg),"%02x:%02x:%02x:%02x:%02x:%02x,   ",
                ap_cur->bssid[0],
                ap_cur->bssid[1],
                ap_cur->bssid[2],
                ap_cur->bssid[3],
                ap_cur->bssid[4],
                ap_cur->bssid[5]);
        sprintf(msg+strlen(msg), "%-23s, ", securitystr);
        sprintf(msg+strlen(msg),"%-9d", Rssi_Quality);
        sprintf(msg+strlen(msg),"\n");

        ap_cur = ap_cur->prev;
    }
    printf("%s", msg);
    free(msg);
}

void update_rx_quality( )
{
    unsigned int time_diff, capt_time, miss_time;
    int missed_frames;
    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    struct timeval cur_time;

    ap_cur = G.ap_1st;
    st_cur = G.st_1st;

    gettimeofday( &cur_time, NULL );

    /* accesspoints */
    while( ap_cur != NULL )
    {
        time_diff = 1000000 * (cur_time.tv_sec  - ap_cur->ftimer.tv_sec )
            + (cur_time.tv_usec - ap_cur->ftimer.tv_usec);

        /* update every `QLT_TIME`seconds if the rate is low, or every 500ms otherwise */
        if( (ap_cur->fcapt >= QLT_COUNT && time_diff > 500000 ) || time_diff > (QLT_TIME * 1000000) )
        {
            /* at least one frame captured */
            if(ap_cur->fcapt > 1)
            {
                capt_time =   ( 1000000 * (ap_cur->ftimel.tv_sec  - ap_cur->ftimef.tv_sec )    //time between first and last captured frame
                                + (ap_cur->ftimel.tv_usec - ap_cur->ftimef.tv_usec) );

                miss_time =   ( 1000000 * (ap_cur->ftimef.tv_sec  - ap_cur->ftimer.tv_sec )    //time between timer reset and first frame
                                + (ap_cur->ftimef.tv_usec - ap_cur->ftimer.tv_usec) )
                    + ( 1000000 * (cur_time.tv_sec  - ap_cur->ftimel.tv_sec )          //time between last frame and this moment
                        + (cur_time.tv_usec - ap_cur->ftimel.tv_usec) );

                //number of frames missed at the time where no frames were captured; extrapolated by assuming a constant framerate
                if(capt_time > 0 && miss_time > 200000)
                {
                    missed_frames = ((float)((float)miss_time/(float)capt_time) * ((float)ap_cur->fcapt + (float)ap_cur->fmiss));
                    ap_cur->fmiss += missed_frames;
                }

                ap_cur->rx_quality = ((float)((float)ap_cur->fcapt / ((float)ap_cur->fcapt + (float)ap_cur->fmiss)) * 100.0);
            }
            else ap_cur->rx_quality = 0; /* no packets -> zero quality */

            /* normalize, in case the seq numbers are not iterating */
            if(ap_cur->rx_quality > 100) ap_cur->rx_quality = 100;
            if(ap_cur->rx_quality < 0  ) ap_cur->rx_quality =   0;

            /* reset variables */
            ap_cur->fcapt = 0;
            ap_cur->fmiss = 0;
            gettimeofday( &(ap_cur->ftimer) ,NULL);
        }
        ap_cur = ap_cur->next;
    }

    /* stations */
    while( st_cur != NULL )
    {
        time_diff = 1000000 * (cur_time.tv_sec  - st_cur->ftimer.tv_sec )
            + (cur_time.tv_usec - st_cur->ftimer.tv_usec);

        if( time_diff > 10000000 )
        {
            st_cur->missed = 0;
            gettimeofday( &(st_cur->ftimer), NULL );
        }

        st_cur = st_cur->next;
    }

}

void imlink_scan_existing_aps(struct wif *wi[], int *fd_raw, int *fdh, int cards)
{
    long cycle_time;
    int caplen=0, fd_is_set, chan_count;
    int wi_read_failed=0;
    int i,chan;
    fd_set  rfds;
    char ifnam[64];
    struct rx_info ri;
    unsigned char      buffer[2048];
    unsigned char      *h80211;
    struct timeval     tv0;
    struct timeval     tv1;
    struct timeval     tv2;
    struct timeval     tv3;

    gettimeofday( &tv0, NULL );
    gettimeofday( &tv1, NULL );
    gettimeofday( &tv2, NULL );
    gettimeofday( &tv3, NULL );

    //use channels
    chan_count = getchancount(1);

    while(1)
    {
        gettimeofday( &tv2, NULL );
        cycle_time = 1000000 * ( tv2.tv_sec  - tv3.tv_sec  )
            + ( tv2.tv_usec - tv3.tv_usec );

        //scan timeout
        if( cycle_time > 2000000)
        {
            break;
        }

        for(chan = 1; chan < 14; chan++)
        {
            //only one card
            wi_set_channel(wi[0], chan);
            G.singlechan = 1;

            //usleep(100);
            while( 1 )
            {
                if( G.do_exit )
                {
                    break;
                }  

                gettimeofday( &tv0, NULL );
                cycle_time = 1000000 * ( tv0.tv_sec  - tv1.tv_sec  )
                    + ( tv0.tv_usec - tv1.tv_usec );

                //scan timeout
                if( cycle_time > 300000 )
                {
                    update_rx_quality();
                    check_monitor(wi, fd_raw, fdh, cards);
                    check_channel(wi, cards);
                    //check_frequency(wi, cards);
                    gettimeofday( &tv1, NULL );
                    break;
                }

                /* capture one packet */
                FD_ZERO( &rfds );
                for(i=0; i<cards; i++)
                    FD_SET( fd_raw[i], &rfds );
                tv0.tv_sec  = G.update_s;
                tv0.tv_usec = (G.update_s == 0) ? REFRESH_RATE : 0;

                if( select( (*fdh) + 1, &rfds, NULL, NULL, &tv0 ) < 0 )
                {
                    if( errno == EINTR )
                    {
                        continue;
                    }
                    perror( "select failed" );

                    return;
                }
                else
                    usleep(1);

                fd_is_set = 0;
                for( i =0; i<cards; i++) 
                {
                    if( FD_ISSET( fd_raw[i], &rfds ) )
                    {
                        memset(buffer, 0, sizeof(buffer));
                        h80211 = buffer;
                        if ((caplen = wi_read(wi[i], h80211, sizeof(buffer), &ri)) == -1) {
                            wi_read_failed++;
                            if(wi_read_failed > 1)
                            {
                                G.do_exit = 1;
                                break;
                            }
                            memset(G.message, '\x00', sizeof(G.message));
                            snprintf(G.message, sizeof(G.message), "][ interface %s down ", wi_get_ifname(wi[i]));

                            //reopen in monitor mode
                            strncpy(ifnam[i], wi_get_ifname(wi[i]), sizeof(ifnam)-1);
                            ifnam[sizeof(ifnam)-1] = 0;

                            wi_close(wi[i]);
                            wi[i] = wi_open(ifnam);
                            if (!wi[i]) {
                                printf("Can't reopen %s\n", ifnam);
                                /* Restore terminal */
                                fprintf( stderr, "\33[?25h" );
                                fflush( stdout );
                                exit(1);
                            }

                            fd_raw[i] = wi_fd(wi[i]);
                            if (fd_raw[i] > *fdh)
                                *fdh = fd_raw[i];

                            break;
                            //                         return 1;
                        }
                        read_pkts++;
                        dump_add_packet( h80211, caplen, &ri, 0 );
                        wi_read_failed = 0;

                    }
                }
            }
        }
        break;
    }

    iwscan_print_aplist();
}

int main( int argc, char *argv[] )
{
    long time_slept;
    int i, fdh, fd_is_set, chan_count;
    int fd_raw[MAX_CARDS], arptype[MAX_CARDS];
    int valid_channel;

    struct AP_info *ap_cur, *ap_prv, *ap_next;
    struct ST_info *st_cur, *st_next;
    struct NA_info *na_cur, *na_next;

    struct wif	       *wi[MAX_CARDS];
    unsigned char      buffer[4096];
    unsigned char      *h80211;
    char               *iface[MAX_CARDS];
    /* initialize a bunch of variables */

    memset( &G, 0, sizeof( G ) );

    h80211         =  NULL;
    G.chanoption   =  0;
    G.freqoption   =  0;
    G.num_cards	   =  0;
    fdh		   =  0;
    fd_is_set	   =  0;
    chan_count	   =  0;
    time_slept     =  0;
    G.batt         =  NULL;
    G.chswitch     =  0;
    valid_channel  =  0;
    G.usegpsd      =  0;
    G.channels     =  bg_chans;
    G.one_beacon   =  1;
    G.singlechan   =  0;
    G.singlefreq   =  0;
    G.dump_prefix  =  NULL;
    G.record_data  =  0;
    G.f_cap        =  NULL;
    G.f_ivs        =  NULL;
    G.f_txt        =  NULL;
    G.f_kis        =  NULL;
    G.f_kis_xml    =  NULL;
    G.f_gps        =  NULL;
    G.keyout       =  NULL;
    G.f_xor        =  NULL;
    G.sk_len       =  0;
    G.sk_len2      =  0;
    G.sk_start     =  0;
    G.prefix       =  NULL;
    G.f_encrypt    =  0;
    G.asso_client  =  0;
    G.f_essid      =  NULL;
    G.f_essid_count = 0;
    G.active_scan_sim  =  0;
    G.update_s     =  0;
    G.decloak      =  1;
    G.is_berlin    =  0;
    G.numaps       =  0;
    G.maxnumaps    =  0;
    G.berlin       =  120;
    G.show_ap      =  1;
    G.show_sta     =  1;
    G.show_ack     =  0;
    G.hide_known   =  0;
    G.maxsize_essid_seen  =  5; // Initial value: length of "ESSID"
    G.show_manufacturer = 0;
    G.show_uptime  = 0;
    G.hopfreq      =  DEFAULT_HOPFREQ;
    G.s_file       =  NULL;
    G.s_iface      =  NULL;
    G.f_cap_in     =  NULL;
    G.detect_anomaly = 0;
    G.airodump_start_time = NULL;

    // Default selection.
    resetSelection();

    memset(G.sharedkey, '\x00', 512*3);
    memset(G.message, '\x00', sizeof(G.message));
    memset(&G.pfh_in, '\x00', sizeof(struct pcap_file_header));

    for(i=0; i<MAX_CARDS; i++)
    {
        arptype[i]=0;
        fd_raw[i]=-1;
        G.channel[i]=0;
    }

    memset(G.f_bssid, '\x00', 6);
    memset(G.f_netmask, '\x00', 6);
    memset(G.wpa_bssid, '\x00', 6);

    G.s_iface = "mon0";

    /* initialize cards */
    G.num_cards = init_cards(G.s_iface, iface, wi);

    if(G.num_cards <= 0)
        return( 1 );

    for (i = 0; i < G.num_cards; i++) {
        fd_raw[i] = wi_fd(wi[i]);
        if (fd_raw[i] > fdh)
            fdh = fd_raw[i];
    }

    //use channels
    chan_count = getchancount(0);

    /* Drop privileges */
    if (setuid( getuid() ) == -1) {
        perror("setuid");
    }

    signal( SIGINT,   sighandler );
    signal( SIGSEGV,  sighandler );
    signal( SIGTERM,  sighandler );
    signal( SIGWINCH, sighandler );

    sighandler( SIGWINCH );

    imlink_scan_existing_aps(wi, fd_raw, &fdh, G.num_cards);

    if(G.elapsed_time)
        free(G.elapsed_time);

    if(G.own_channels)
        free(G.own_channels);
    
    if(G.f_essid)
        free(G.f_essid);

    if(G.prefix)
        free(G.prefix);

    if(G.f_cap_name)
        free(G.f_cap_name);

    for(i=0; i<G.num_cards; i++)
        wi_close(wi[i]);
    
    if( ! G.save_gps )
    {
        snprintf( (char *) buffer, 4096, "%s-%02d.gps", argv[2], G.f_index );
        unlink(  (char *) buffer );
    }

    ap_prv = NULL;
    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
        // Clean content of ap_cur list (first element: G.ap_1st)
        uniqueiv_wipe( ap_cur->uiv_root );

        list_tail_free(&(ap_cur->packets));

        if (G.manufList)
            free(ap_cur->manuf);

        if (G.detect_anomaly)
            data_wipe(ap_cur->data_root);

        ap_prv = ap_cur;
        ap_cur = ap_cur->next;
    }

    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
        // Freeing AP List
        ap_next = ap_cur->next;

        if( ap_cur != NULL )
            free(ap_cur);

        ap_cur = ap_next;
    }

    st_cur = G.st_1st;
    st_next= NULL;

    while(st_cur != NULL)
    {
        st_next = st_cur->next;
        if (G.manufList)
            free(st_cur->manuf);
        free(st_cur);
        st_cur = st_next;
    }

    na_cur = G.na_1st;
    na_next= NULL;

    while(na_cur != NULL)
    {
        na_next = na_cur->next;
        free(na_cur);
        na_cur = na_next;
    }

    fprintf( stderr, "\33[?25h" );
    fflush( stdout );

    return( 0 );
}
