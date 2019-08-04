#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include "struct.h"

struct ethernet eth;
struct arp arp;
struct ip ip;
struct tcp tcp;
struct udp udp;
struct http http;
void eth_print(const u_char* ptr){
    memcpy(eth.descMac,ptr,6);
    memcpy(eth.srcMac,ptr=ptr+6,6);
    eth.ethType = *(ptr=ptr+6) << 8 | *(ptr=ptr+1);
    printf("Dest \tMac : \t");
    for(int i=0;i<6;i++){
        if(i<5)
            printf("%02x:",eth.descMac[i]);
        else
            printf("%02x\n",eth.descMac[i]);
    }
    printf("Source \tMac : \t");
    for(int i=0;i<6;i++){
        if(i<5)
            printf("%02x:",eth.srcMac[i]);
        else
            printf("%02x\n",eth.srcMac[i]);
    }
    if(eth.ethType == 0x0800)
        printf("Type : IPv4\n");
    else if(eth.ethType == 0x0806)
        printf("Type : ARP\n");
    else if(eth.ethType == 0x0835)
        printf("Type : RARP\n");
    else if(eth.ethType == 0x86DD)
        printf("Protocol : IPv6\n");
}
void arp_print(const u_char* ptr){
    arp.hwType = *(ptr=ptr+0) << 8 | *(ptr=ptr+1);
    arp.procType = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    arp.hwSize = *(ptr=ptr+1);
    arp.procSize = *(ptr=ptr+1);
    arp.opcode = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    memcpy(arp.sendMac, ptr=ptr+1, 6);
    memcpy(&arp.sendIp, ptr=ptr+6, 4);
    memcpy(arp.targetMac, ptr=ptr+4, 6);
    memcpy(&arp.targetIp, ptr=ptr+6, 4);
    printf("Hardware Type : ");
    if(arp.hwType == 1){
        printf("Ethernet\n");
    }else if(arp.hwType == 15){
        printf("Frame Relay\n");
    }else if(arp.hwType == 17){
        printf("HDLC\n");
    }else if(arp.hwType == 20){
        printf("Serial Line\n");
    }

    if(arp.procType == 0x0800)
        printf("Protocol Type : IPv4 (0x0800)\n");

    printf("Hardware Size : %d\n",arp.hwSize);
    printf("Protocol Size : %d\n",arp.procSize);
    printf("Opcode : ");
    if(arp.opcode == 1){
        printf("ARP Request\n");
    }else if(arp.opcode == 2){
        printf("ARP Reply\n");
    }
    printf("Sender Hardware Address : ");
    for(int i=0;i<6;i++){
        if(i != 5)
            printf("%02x:",arp.sendMac[i]);
        else
            printf("%02x\n",arp.sendMac[i]);
    }
    printf("Sender Protocol Address : ");

    printf("Target Hardware Address : ");
    for(int i=0;i<6;i++){
        if(i != 5)
            printf("%02x:",arp.targetMac[i]);
        else
            printf("%02x\n",arp.targetMac[i]);
    }
    printf("Sender Protocol Address : ");

}
void ip_print(const u_char* ptr){
    u_char val_v_len = *ptr;
    ip.version = (val_v_len & 0xF0)>>4;
    ip.hdrLen = (val_v_len & 0x0F)*4;
    uint8_t val_dscp = *(ptr=ptr+1);
    uint8_t DSCP[2];
    DSCP[0] = (val_dscp & 0xFC);
    DSCP[1] = (val_dscp & 0x3);
    ip.totLen = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.ID = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.flags = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    ip.ttl = *(ptr=ptr+1);
    ip.protocol = *(ptr=ptr+1);
    ip.chksum = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    memcpy(ip.srcIp, ptr=ptr+1, 4);
    memcpy(ip.destIp, ptr=ptr+4, 4);


    if(ip.version == 4)
        printf("Version : IPv4\n");
    else if(ip.version == 6)
        printf("Version : IPv6\n");

    //printf("Identification : 0x%04x\n", ip.ID);
    //printf("Flags 0x%04x\n",ip.flags);
    //printf("Time to live : %d\n",ip.ttl);
    //if(ip.protocol == 0x01)
    //    printf("Protocol : ICMP\n");
    if(ip.protocol == 0x06){
        printf("Protocol : TCP\n");
        printf("Header Length : %d\n",ip.hdrLen);
        printf("Total Length : %d\n",ip.totLen);
        printf("Source IP : %d.%d.%d.%d\n",ip.srcIp[0],ip.srcIp[1],ip.srcIp[2],ip.srcIp[3]);
        printf("Destination IP : %d.%d.%d.%d\n",ip.destIp[0],ip.destIp[1],ip.destIp[2],ip.destIp[3]);
    }else if(ip.protocol == 0x11)
        printf("Protocol : UDP\n");
    else if(ip.protocol == 0x29)
        printf("Protocol : IPv6\n");
    //printf("CheckSum : 0x%04x\n", ip.chksum);
}
void tcp_print(const u_char* ptr){
    tcp.srcPort = *(ptr) << 8 | *(ptr=ptr+1);
    tcp.destPort = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    if(tcp.destPort == 80){
        printf("Source Port : %d\n", tcp.srcPort);
        printf("Destination Port : %d\n", tcp.destPort);
        tcp.hdrLen = (*(ptr=ptr+9) >> 4)*4;
        printf("Header Length : %d\n",tcp.hdrLen);
    }else if(tcp.destPort == 443){
        printf("Source Port : %d\n", tcp.srcPort);
        printf("Destination Port : %d\n", tcp.destPort);
        tcp.hdrLen = (*(ptr=ptr+9) >> 4)*4;
        printf("Header Length : %d\n",tcp.hdrLen);
    }
}
void udp_print(const u_char* ptr){
    udp.srcPort = *(ptr) << 8 | *(ptr=ptr+1);
    udp.destPort = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
    if(udp.destPort == 80){
        printf("Source Port : %d\n", udp.srcPort);
        printf("Destination Port : %d\n", udp.destPort);
        udp.len = *(ptr=ptr+1) << 8 | *(ptr=ptr+1);
        printf("Length : %d\n",udp.len);
        memcpy(udp.data,ptr=ptr+3, udp.len-8);
        printf("Data : %s\n",udp.data);
    }

}
void http_print(const u_char* ptr){
    printf("HTTP Data : ");
    for(int i=0;i<10;i++){
        if(0x20 <= *ptr+i || *ptr+i <= 0x80)
            printf("%c", *(ptr+i));
        else
            continue;
        if(*ptr+i=='\x0d' && *(ptr+i+1) =='\x0a')
            break;
    }
    printf("\n");
}
void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}
void printchar(unsigned char c)
{
    if(isprint(c))
        printf("%c",c);
    else
        printf(".");
}

void dumpcode(unsigned char *buff, int len)
{
    int i;
    for(i=0;i<len;i++)
    {

        if(i%16==0)
            printf("0x%08x ",&buff[i]);

        printf("%02x ",buff[i]);

        if(i%16-15==0)
        {
            int j;
            printf(" ");
            for(j=i-15;j<=i;j++)
                printchar(buff[j]);
            printf("\n");
        }
    }

    if(i%16!=0)
    {
        int j;
        int spaces=(len-i+16-i%16)*3+2;
        for(j=0;j<spaces;j++)
            printf(" ");
        for(j=i-i%16;j<len;j++)
            printchar(buff[j]);
    }
    printf("\n");
}

void make_ip(uint8_t* dest, char* ip){
    char* sptr = strtok(ip, ".");
    int i=0;
    while(sptr != NULL){
        dest[i] = atoi(sptr);
        sptr = strtok(NULL, ".");
        i++;
    }
}
void make_packet(u_char* ptr, uint8_t* smac, uint8_t* tmac, char* sip, char* tip){

    struct ethernet* eth = reinterpret_cast<struct ethernet*>(ptr);
    for(int i=0;i<6;i++){
        eth->descMac[i] = 0xff;
    }
    for(int i=0;i<6;i++){
        eth->srcMac[i] = smac[i];
    }

    eth->ethType = htons(0x806);
    struct arp* arp = reinterpret_cast<struct arp*>(ptr=ptr+14);
    arp->hwType = htons(0x0001);
    arp->procType = htons(0x800);
    arp->hwSize = 0x06;
    arp->procSize = 0x4;
    arp->opcode = htons(0x0001);
    for(int i=0;i<6;i++){
        arp->sendMac[i] = smac[i];
    }
    make_ip(arp->sendIp, sip);
    for(int i=0;i<6;i++){
        arp->targetMac[i] = tmac[i];
    }
    make_ip(arp->targetIp, tip);

}
int main(int argc, char* argv[]) {
    char* dev = argv[1];
    char* sendip = argv[2];
    char* targetip=argv[3];

    uint8_t smac[6] = {0x00,0x0c,0x29,0xb5,0x8e,0x5d};
    uint8_t tmac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[0x3c];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        make_packet(packet, smac,tmac, sendip,targetip);
        if(pcap_sendpacket(handle, packet,0x3c) != 0){
            fprintf(stderr, "\nError Sending the packet: %s\n",pcap_geterr(handle));
        }
        sleep(3);
        printf("================================\n");
        dumpcode(packet, 0x3c);
        printf("================================\n");

    }

    pcap_close(handle);
    free(packet);
    return 0;
}
