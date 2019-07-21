#ifndef HEAD_H
#define HEAD_H
#include <pcap.h>
#include <netinet/ip.h>

#define ETH_LEN 6
#define IP_LEN 4
#define TCP_LEN 2
#define IP_TYPE 0x0800
#define TCP_TYPE 6

typedef struct _eth_hdr eth_hdr;
struct _eth_hdr{
    u_char dst[ETH_LEN];
    u_char src[ETH_LEN];
    u_short type;

};
#define SIZE_ETH (sizeof(eth_hdr))

typedef struct _ip_hdr ip_hdr;
struct _ip_hdr{
     u_char hd_len:4;
     u_char version:4;

     u_int8_t ip_tos;
     u_short ip_len;
     u_short ip_id;
     u_short ip_off;

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
     u_int8_t ip_ttl;
     u_int8_t ip_p;
     u_short ip_sum;

     u_char src_add[IP_LEN];
     u_char dest_add[IP_LEN];
};
#define SIZE_IP (sizeof(ip_hdr))

typedef struct _tcp_hdr tcp_hdr;
struct _tcp_hdr{
    u_char src_port[TCP_LEN];
    u_char dest_port[TCP_LEN];

    u_int seq;
    u_int ack;

    u_short reserved:4;
    u_short doff:4;

    u_char flags;
    #define TCP_FIN   0x01
    #define TCP_SYN   0x02
    #define TCP_RST   0x04
    #define TCP_PUSH  0x08
    #define TCP_ACK   0x10
    #define TCP_URG   0x20

    u_short window;
    u_short check;
    u_short urgent;
};
#define SIZE_TCP (sizeof(tcp_hdr))
#endif // HEAD_H
