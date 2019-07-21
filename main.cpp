#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include "head.h"

int tcp_size = 0;
u_int16_t ip_type = 0;
u_int8_t tcp_type = 0;

void ethernet(const u_char *packet){
    eth_hdr *ehd = (eth_hdr*)packet;
    printf("====================== Ethernet Header ====================\n");
    printf("Destination mac :             %02x:%02x:%02x:%02x:%02x:%02x\n", ehd->dst[0], ehd->dst[1], ehd->dst[2], ehd->dst[3], ehd->dst[4], ehd->dst[5]);
    printf("Source mac      :             %02x:%02x:%02x:%02x:%02x:%02x\n", ehd->src[0], ehd->src[1], ehd->src[2], ehd->src[3], ehd->src[4], ehd->src[5]);
    ip_type = ntohs(ehd->type);
}

void ip(const u_char *packet){
    ip_hdr *ihd = (ip_hdr*)packet;
    printf("========================= IP Header =======================\n");
    printf("Source IP       :             %u.%u.%u.%u\n", ihd->src_add[0],ihd->src_add[1],ihd->src_add[2],ihd->src_add[3]);
    printf("Destination IP  :             %u.%u.%u.%u\n", ihd->dest_add[0], ihd->dest_add[1], ihd->dest_add[2], ihd->dest_add[3]);
    tcp_type = ihd->ip_p;
}

void tcp(const u_char *packet){
    tcp_hdr *thd = (tcp_hdr*)packet;
    printf("======================== TCP Header =======================\n");
    printf("Source Port     :             %d\n", (thd->src_port[0] << 8) | thd->src_port[1]);
    printf("Destination Port:             %d\n", (thd->dest_port[0] << 8) | thd->dest_port[1]);
    tcp_size = (thd->doff * 4);
}

void tcp_data(const u_char *packet){
    int len = 10;
    printf("TCP Data        :             ");
    while(len--){
        if(*(packet) == 0x00){
            printf("NONE\n");
            break;
        }
        printf("%x", *packet);
        packet++;
    }

}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
  char track[] = "취약점";
  char name[] = "남훈";
  printf("[bob8][%s]pcap_test[%s]\n", track, name);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    ethernet(packet);
    if(ip_type == IP_TYPE){
        ip(&packet[SIZE_ETH]);
    }
    else{
        printf("========================= IP Header =======================\n");
        printf("NONE\n");
    }

    if(tcp_type == TCP_TYPE){
        tcp(&packet[SIZE_ETH+SIZE_IP]);
    }
    else{
        printf("======================== TCP Header =======================\n");
        printf("NONE\n");
    }

    if(header->caplen == SIZE_ETH+SIZE_IP+tcp_size){
        printf("TCP Data        :             NONE\n");
    }
    else{
        tcp_data(&packet[SIZE_ETH+SIZE_IP+tcp_size]);
    }
    printf("\n\n\n");
  }

  pcap_close(handle);
  return 0;
}
