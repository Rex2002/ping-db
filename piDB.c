// cd /run/media/harka/0AA03EE9A03EDAC1/Users/Win10/Data/Programmierung/C/pDB/

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE


#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>


#define PING_PKT_S 64
#define PING_PKT_PAYLOAD_SIZE 37
#define PKT_ID_SIZE 3
#define PKT_PAYLOAD_SIZE 34
#define RESPONSE_CONTENT_OFFSET 20
#define PORT_NO 0 
#define RECV_TIMEOUT 1 

int pingLoop = 1;


struct ping_pkt{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};
typedef struct data_pkt{
    unsigned int id : 24;
    int data_len;
    char *data;
} data_pkt;
typedef struct ping_pkt packet;

void intHandler(int dummy)
{
    printf("int handler called with dummy: %i \n", dummy);
    pingLoop=0;
}

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con){
    printf("\nResolving DNS..\n");
    struct hostent *host_entity;
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
 
    if ((host_entity = gethostbyname(addr_host)) == NULL)
    {
        // No ip found for hostname
        return NULL;
    }
     
    //filling up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)
                          host_entity->h_addr));
 
    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons (PORT_NO);
    (*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr;
 
    return ip;  
}

unsigned short checksum(void *b, int len)
{    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;
 
    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int dataPkt2char(data_pkt data_pkt, char *out_buf){
    char id1 = (data_pkt.id >> (8*0)) & 0xff;
    char id2 = (data_pkt.id >> (8*1)) & 0xff;
    char id3 = (data_pkt.id >> (8*2)) & 0xff;
    out_buf[0] = id1;
    out_buf[1] = id2;
    out_buf[2] = id3;
    if(data_pkt.data_len > PING_PKT_PAYLOAD_SIZE - 3){
        printf("invalid data packet detected: %s\n", data_pkt.data);
        out_buf[3] = 0;
        return 3;
    }
    printf("payload: %s, id1: %i, %i, %i\n", data_pkt.data, id1, id2, id3);
    int i;
    for(i = 3; i < data_pkt.data_len; i++){
        out_buf[i] = data_pkt.data[i-3];
    }
    return i;
}

void printPcktMsg(char* msg, int size){
    int i = 0;
    for(; i < 3; i++){
        printf("%i", msg[i]);
    }
    for(; i < size; i++){
        printf("%c", msg[i]);
    }
    printf("\n");
}

packet prepPckt(packet pckt, char *content, int content_len, int *msg_count){
    printf("prepping with message: ");
    printPcktMsg(content, content_len);
    printf("message size: %i\n", content_len);
    int i;
    memset(&pckt, 0, sizeof(pckt));
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = getpid();
    for(i = 0; i < content_len; i++){
        pckt.msg[i] = content[i];
    }
    for (;i < (int) sizeof(pckt.msg)-1; i++ )
        pckt.msg[i] = i+70; 

    pckt.msg[i] = 0;
    pckt.hdr.un.echo.sequence = 1;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
    return pckt;
}


void sendPing(int ping_sockfd, packet *pck, struct sockaddr_in *ping_addr){
    if(sendto(ping_sockfd, pck, sizeof(*pck), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0){
        printf("failed to send packet\n");
        printf("errno: %s\n", strerror(errno));
    }
    printf("sent message: ");
    printPcktMsg(pck->msg, sizeof(pck->msg));
}

void recvPing(int ping_sockfd, packet *pck){
    struct sockaddr_in r_addr;
    unsigned int addr_len = sizeof(r_addr);
    if(recvfrom(ping_sockfd, pck, sizeof(*pck), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0){
        printf("failed to receive packet \n");
        printf("errno: %s\n", strerror(errno));
        return;
    }
    else{
        printf("recv message: ");
        printPcktMsg(pck->msg, sizeof(pck->msg));
    }
}

void pongPing(int ping_sockfd, packet *pck, struct sockaddr_in addrs[], int addrs_len){
    packet pckSend;
    struct timeval begin, end;
    sendPing(ping_sockfd, pck, addrs);
    // input a list of packets, send all of them quickly, afterwards only use one buffer pck and work on resending them
    while(pingLoop){
        gettimeofday(&begin, 0);
        recvPing(ping_sockfd, pck);
        pckSend = prepPckt(*pck, &(pck->msg)[RESPONSE_CONTENT_OFFSET], 36, 0);
        sendPing(ping_sockfd, &pckSend, &addrs[rand()%addrs_len]);
        usleep(1000000);
        gettimeofday(&end, 0);
        printf("elapsed time: %f\n", (end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec) * 1e-6);
        usleep(1000000);
    }
}

int main(){
    srand(0);
    int sockfd, msg_count = 0, ttl_val = 64;
    
    struct timeval tv_out;

    packet pckt; 
    data_pkt data = {257, 24, "sending packet > 0 STOP"};
    char *targets[] = {"localhost", "yahoo.com", "google.com", "ekg-ahrensburg.de"}; 
    int target_len = sizeof(targets)/sizeof(targets[0]);
    struct sockaddr_in addr_cons[target_len];
    char *ip_addrs[target_len];
    for(int i = 0; i < target_len; i++){
        ip_addrs[i] = dns_lookup(targets[i], &(addr_cons[i]));
        printf("resolved %s to %s\n", targets[i], *(ip_addrs + i));
    }


    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0){
        printf("failed to receive socket file descriptor\n");
        exit(0);
    }
    printf("socket file descriptor received: %d\n", sockfd);


    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0){
        printf("\nSetting socket options to TTL failed!\n");
        printf("errno: %s\n", strerror(errno));
        exit(0);
        
    }
    else{
        printf("\nSocket set to TTL..\n");
    }
 
    // setting timeout of recv setting
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   (const char*)&tv_out, sizeof tv_out);

    char data_char[PING_PKT_PAYLOAD_SIZE];
    int data_len = dataPkt2char(data, data_char);
    pckt = prepPckt(pckt, data_char, data_len, &msg_count);
    pongPing(sockfd, &pckt, addr_cons, target_len);
    exit(0);
}