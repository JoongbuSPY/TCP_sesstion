#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include "tcp.hpp"



int main()

{

    Call_Device(&dev);
    Pcap_Init(&dev,&p_handle);
    pcap_loop(p_handle, -1, p_packet, NULL);
    pcap_close(p_handle);

    return(0);

}

void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{

    libnet_ethernet_hdr *p_ether = (libnet_ethernet_hdr *)p;

    if((ntohs(p_ether->ether_type)== ETHERTYPE_IP))
    {
        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        if(p_ip->ip_p == IPPROTO_TCP)
        {
           libnet_tcp_hdr * p_tcp = (libnet_tcp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));

           int tcp_header_len = p_tcp->th_off * 4;
           printf("tcp_header_len: %d \n",tcp_header_len);

           int tcp_data_len = ntohs(p_ip->ip_len)-sizeof(libnet_ipv4_hdr) - tcp_header_len;
           printf("tcp_data_len: %d \n",tcp_data_len);

           char * tcp_data = (char *)(p_tcp)+tcp_header_len;

           printf("%s \n",tcp_data);






        }

    }
}


