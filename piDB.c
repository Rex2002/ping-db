#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE


#include <netinet/ip_icmp.h>
#include <netinet/in.h>
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
#define PORT_NO 0 
#define RECV_TIMEOUT 1 



struct ping_pkt
{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};
typedef struct ping_pkt packet;


char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
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

void prepPckt(struct ping_pkt* pckt, int *msg_count){
    int i;
    memset(pckt, 0, sizeof(*pckt));
    pckt->hdr.type = ICMP_ECHO;
    pckt->hdr.un.echo.id = getpid();
    sprintf(pckt->msg, "sending packet no > %i. STOP", (*msg_count));
    for (i = 27; i < (int) sizeof(pckt->msg)-1; i++ )
        pckt->msg[i] = i+70; 

    pckt->msg[i] = 0;
    printf("Packet: %s, Size: %lu \n", pckt->msg, sizeof(pckt->msg));
    pckt->hdr.un.echo.sequence = (*msg_count)++;
    pckt->hdr.checksum = checksum(&pckt, sizeof(pckt));
}

void printPcktMsg(char* msg, int size){
    for(int i = 0; i < size; i++){
        printf("%c", msg[i]);
    }
    printf("\n");
}

void sendPing(int ping_sockfd, packet *pck, struct sockaddr_in *ping_addr){
    printPcktMsg(pck->msg, sizeof(pck->msg));
    char *s = inet_ntoa(ping_addr->sin_addr);
    printf("IP address: %s\n", s);
    if(sendto(ping_sockfd, pck, sizeof(pck), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0){
        printf("failed to send packet\n");
        printf("errno: %s\n", strerror(errno));
    }
}

void recvPing(int ping_sockfd, packet *pck, struct sockaddr_in *ping_addr){
    
}

int main(){
    int sockfd, msg_count = 0, ttl_val = 64;
    struct sockaddr_in addr_con;
    struct timeval tv_out;

    packet pckt; 
    char *ip_addr;
    char * target = "localhost";
    ip_addr = dns_lookup(target, &addr_con);
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

    prepPckt(&pckt, &msg_count);

    printf("ip_addr: %s\n", ip_addr );
    sendPing(sockfd, &pckt , &addr_con);
    exit(0);
}