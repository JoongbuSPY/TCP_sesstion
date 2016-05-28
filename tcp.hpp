#ifndef TCP_HPP
#define TCP_HPP

void Call_Device(char **C_dev);
int Pcap_Init(char **P_dev, pcap_t *P_handle);
void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);



pcap_t *p_handle;            /* Session handle */
char *dev;            /* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */



void Call_Device(char **C_dev)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char Select_device[10];
    char errbuf[PCAP_ERRBUF_SIZE];


    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    /* Print the list */
    for(d=alldevs;d;d=d->next)
        printf("%d. %s \n", ++i, d->name);


    if(i==0)
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");

    printf("\nSelect Device: ");
    scanf("%s",&Select_device);


    *C_dev=Select_device;


    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
}

int Pcap_Init(char **P_dev, pcap_t **P_handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if ((*P_handle = pcap_open_live(*P_dev, BUFSIZ, 1, 1000, errbuf)) == NULL)
    {
        printf("Couldn't open device \n");
        return(2);
    }

    else
         printf("\t\t\t\t\t\t\t\t  Pcap_Open_Live \t\t\t\t\t\t\t\t\t    <OK>\n");

}







#endif // TCP_HPP
