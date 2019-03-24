#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
uint8_t packet[]= {
    "\x00\x1c\x42\x00\x00\x18\x00\x1c\x42\x1a\xf8\xa5\x08\x00\x45\x00" \
    "\x01\x7d\x81\x5b\x40\x00\x40\x06\xa3\x4c\x0a\xd3\x37\x04\xaf\xd5" \
    "\x23\x27\xb3\xee\x00\x50\x91\xf6\x65\x87\xab\xc3\x5a\x62\x50\x18" \
    "\x00\xe5\x16\x43\x00\x00\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50" \
    "\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x74\x65\x73\x74" \
    "\x2e\x67\x69\x6c\x67\x69\x6c\x2e\x6e\x65\x74\x0d\x0a\x55\x73\x65" \
    "\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61" \
    "\x2f\x35\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x4c\x69\x6e\x75\x78" \
    "\x20\x78\x38\x36\x5f\x36\x34\x3b\x20\x72\x76\x3a\x35\x32\x2e\x30" \
    "\x29\x20\x47\x65\x63\x6b\x6f\x2f\x32\x30\x31\x30\x30\x31\x30\x31" \
    "\x20\x46\x69\x72\x65\x66\x6f\x78\x2f\x35\x32\x2e\x30\x0d\x0a\x41" \
    "\x63\x63\x65\x70\x74\x3a\x20\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c" \
    "\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74" \
    "\x6d\x6c\x2b\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69" \
    "\x6f\x6e\x2f\x78\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x2a\x2f\x2a" \
    "\x3b\x71\x3d\x30\x2e\x38\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c" \
    "\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x55\x53\x2c\x65" \
    "\x6e\x3b\x71\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d" \
    "\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x20" \
    "\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74" \
    "\x69\x6f\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d" \
    "\x0a\x55\x70\x67\x72\x61\x64\x65\x2d\x49\x6e\x73\x65\x63\x75\x72" \
    "\x65\x2d\x52\x65\x71\x75\x65\x73\x74\x73\x3a\x20\x31\x0d\x0a\x43" \
    "\x61\x63\x68\x65\x2d\x43\x6f\x6e\x74\x72\x6f\x6c\x3a\x20\x6d\x61" \
    "\x78\x2d\x61\x67\x65\x3d\x30\x0d\x0a\x0d\x0a"


};
struct ethernet_h{
    uint8_t Dm[6];
    uint8_t Sm[6];
    uint16_t ether_type;
};

struct ip_h{
    uint8_t hdr_len:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t lden;
    uint16_t offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

};

struct port_h{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t reserved;
    uint8_t window;
    uint8_t cheksum1;
    uint8_t urgent_pointer;


};

struct arp_h{
    uint16_t Hardware_type;
    uint16_t Protocol_type;
    uint8_t Hawa_address_length;
    uint8_t Pr_address_length;
    uint16_t Opcode;
    uint8_t Src_hardware_add[6];
    uint8_t Src_protocol_add[4];
    uint8_t Dst_hardware_add[6];
    uint8_t Dst_protocol_add[4];


};

/*void viewDM(unsigned char*mac){
    int i;
    for(i=0;i<Dm;i++){
        if(i==5){
            printf("%02X",mac[i]);
            break;
        }
        printf("%02X",mac[i]);
    }
}*/
/*void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
*/
int main(int argc, char* argv[]) {
  if (argc != 2) {
   // usage();
    return -1;
  }
/*
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
*/
    struct ethernet_h *eth_h;
    eth_h = (struct ethernet_h *)(packet);
    printf("--------------------Eth--------------------\n");
    printf("Source MAC %02x:%02x:%02x:%02x:%02x:%02x \n",eth_h->Sm[0],eth_h->Sm[1],
           eth_h->Sm[2],eth_h->Sm[3],eth_h->Sm[4],eth_h->Sm[5]);
    printf("Destinaiton %02x:%02x:%02x:%02x:%02x:%02x \n",eth_h->Dm[0],eth_h->Dm[1],eth_h->Dm[2],eth_h->Dm[3],eth_h->Dm[4],eth_h->Dm[5]);
    printf("-------------------------------------------\n");

    struct ip_h *ipp_h;
    ipp_h = (struct ip_h *)(packet +14);
    //char buf[16];
    printf("--------------------ip--------------------\n");
    printf("Source IP %d.%d.%d.%d \n",ipp_h->src_ip[0],ipp_h->src_ip[1],
          ipp_h->src_ip[2],ipp_h->src_ip[3]);
    printf("Destinaiton IP %d.%d.%d.%d \n",ipp_h->dst_ip[0],ipp_h->dst_ip[1]
           ,ipp_h->dst_ip[2],ipp_h->dst_ip[3]);
    printf("------------------------------------------\n");
    struct port_h *pport_h;
    pport_h = (struct port_h *)(packet +20 +14);
    printf("-------------------TCP---------------------\n");
    printf("Source Port %d\n",ntohs(pport_h->src_port));
    printf("Destinaiton Port %d\n",ntohs(pport_h->dst_port));
    printf("-------------------------------------------\n");
  //  printf("%u bytes captured\n", header->caplen);

    struct arp_h *arpp_h;
    arpp_h = (struct arp_h *)(packet +14);
    printf("--------------------APR-------------\n");
    printf("Source hardware address %02x:%02x:%02x:%02x:%02x:%02x\n",arpp_h->Src_hardware_add[0],arpp_h->Src_hardware_add[1],arpp_h->Src_hardware_add[2],
            arpp_h->Src_hardware_add[3],arpp_h->Src_hardware_add[4],arpp_h->Src_hardware_add[5]);
    printf("Source protocol address %d.%d.%d.%d\n",arpp_h->Src_protocol_add[0],arpp_h->Src_protocol_add[1],arpp_h->Src_protocol_add[2]
            ,arpp_h->Src_protocol_add[3]);
    printf("Destinaiton hardware address %02x:%02x:%02x:%02x:%02x:%02x\n",arpp_h->Dst_hardware_add[0],arpp_h->Dst_hardware_add[1],arpp_h->Dst_hardware_add[2]
            ,arpp_h->Dst_hardware_add[3],arpp_h->Dst_hardware_add[4],arpp_h->Dst_hardware_add[5]);
    printf("Destinaiton protocol address %d.%d.%d.%d\n",arpp_h->Dst_protocol_add[0],arpp_h->Dst_protocol_add[1],arpp_h->Dst_protocol_add[2]
            ,arpp_h->Dst_protocol_add[3]);
    printf("-------------------------------------------\n");
  }
/* pcap_close(handle);
 return 0;
}
*/
