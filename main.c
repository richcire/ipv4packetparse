#include <stdio.h>
#include <time.h>
#include <stdint.h>

#define FILENAME "HW2_pcap_format.pcap"
#define MAX_PACKET  10000
#define MAC_ADDR_LEN 6
#define DONT_FRAG(frag)   (frag & 0x40)
#define MORE_FRAG(frag)   (frag & 0x20)


typedef struct _packet_header {
   int    tv_sec;        
   int    tv_usec;   
   unsigned caplen;
   unsigned len;    
}packet_header;

typedef struct _ethernet {
   unsigned char dest_mac[MAC_ADDR_LEN];
   unsigned char src_mac[MAC_ADDR_LEN];
   unsigned short type;
}ethernet;

typedef struct _ip_header {
   unsigned char  header_len : 4;
   unsigned char  version : 4;
   unsigned char  tos;
   unsigned short total_len;
   unsigned short id;   
   unsigned short frag;
   unsigned char ttl;
   unsigned char protocol;
   unsigned short checksum;
   unsigned int src_address;
   unsigned int dst_address;
}ip_header;


int Parsing(FILE *fp);

void EthernetInfo(char *buf);

void MacInfo(unsigned char *mac);

unsigned short ntohs(unsigned short value);

void ParsePacket(FILE *fp);

void IPInfo(char *buf);

void PacketHeaderInfo(packet_header *ph);

packet_header headers[MAX_PACKET];

int packet_count;

int main() {

   char fname[256];
   FILE *fp = fopen(FILENAME, "r");
   Parsing(fp);
   fclose(fp);
   return 0;

}

int Parsing(FILE *fp) {
  
   char buffer[25];

   fread(&buffer, sizeof(char)*24, 1, fp);

   ParsePacket(fp);

   return 0;

}

void ParsePacket(FILE *fp) {

   char data[65536];
   packet_header *ph = headers;
   int i = 0;
   while (feof(fp) == 0) {
       if (fread(ph, sizeof(packet_header), 1, fp) != 1) {
           break;
       }
       PacketHeaderInfo(ph); //패킷 헤더 정보
       fread(data, 1, ph->len, fp);
       EthernetInfo(data); //이더넷 정보
       ph++;
   }

}

void PacketHeaderInfo(packet_header *ph) {

   time_t now;
   struct tm ts;
   char buf[80];
   now = (time_t) ph->tv_sec;

   ts = *localtime(&now);
   strftime(buf, sizeof(buf), "%H:%M:%S", &ts);
   packet_count++;
  
   printf("\nNo.%d Arrival Time:%s.%06d   Captured Length:%u byte   Actual Length:%u byte \n", packet_count, buf, ph->tv_usec, ph->caplen, ph->len);

}

void EthernetInfo(char *data) {

   ethernet *ph = (ethernet *)data;

   printf("Src MAC ");
   MacInfo(ph->src_mac);
   printf(" --> Dest MAC ");
   MacInfo(ph->dest_mac);

   IPInfo(data + sizeof(ethernet));
}


void MacInfo(unsigned char *mac_addr) {

   int i;
  
   for (i = 0; i < MAC_ADDR_LEN; ++i) {
       printf(" : %02x", mac_addr[i]);
   }
}

unsigned short ntohs(unsigned short value) {
   return(value << 8) | (value >> 8);
}


#include <arpa/inet.h>

void IPInfo(char *data) {

   ip_header *ip = (ip_header *)data;

   char str[20];
   printf("\nsrc address: %s, ", inet_ntop(2, &(ip->src_address), str, 20));

   printf("dst address: %s\n", inet_ntop(2, &(ip->dst_address), str, 20));

   switch (ip->protocol){
       case 1: printf("ICMP\n"); break;
       case 2: printf("IGMP\n"); break;
       case 6: printf("TCP\n"); break;
       case 17: printf("UDP\n"); break;
       case 89: printf("OSPF\n"); break;
       default: printf("Not support\n"); break;
   }

   printf("Identification: %d, ", ntohs(ip->id));

   if (DONT_FRAG(ip->frag)) {
       printf("DF : 1 MF : 0\n");
   } else {
       if (MORE_FRAG(ip->frag) == 0) {
           printf("DF : 0 MF : 0\n");
       } else {
           printf("DF : 0 MF : 1\n");
       }
   }

   printf("TTL: %d\n", ip->ttl);

   printf("Type of service: %d\n", ip->tos);

   printf("IP Header Length:%d bytes\n", ip->header_len * 4);
}
