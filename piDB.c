// cd /run/media/harka/0AA03EE9A03EDAC1/Users/Win10/Data/Programmierung/C/pDB/

#define _DEFAULT_SOURCE
#define _GNU_SOURCE


#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "queue.c"


#define PING_PKT_S 64
#define PING_PKT_PAYLOAD_SIZE 36
#define PKT_ID_SIZE 3
#define PKT_PAYLOAD_SIZE 33
#define RESPONSE_CONTENT_OFFSET 20
#define PORT_NO 0 
#define RECV_TIMEOUT 1 

int pingLoop = 1;


typedef struct ping_pkt{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
} packet;

void intHandler(int dummy)
{
    printf("int handler called with dummy: %i \n", dummy);
    pingLoop=0;
}

#include "dns_lookup.c"

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

int dataPkt2char(data_pkt pkt, char *out_buf){
    char id1 = (pkt.id >> (8*0)) & 0xff;
    char id2 = (pkt.id >> (8*1)) & 0xff;
    char id3 = (pkt.id >> (8*2)) & 0xff;
    out_buf[0] = id1;
    out_buf[1] = id2;
    out_buf[2] = id3;
    if(pkt.data_len > PING_PKT_PAYLOAD_SIZE - 3){
        printf("invalid data packet detected: %s\n", pkt.data);
        out_buf[3] = 0;
        return 3;
    }
    printf("payload: %s, id1: %i, %i, %i\n", pkt.data, id1, id2, id3);
    int i;
    //strlcpy( &out_buf[3], pkt.data, pkt.data_len-1); 
    for(i = 0; i < pkt.data_len; i++){
        out_buf[i+3] = pkt.data[i];
    }
    printf("outbuf %s\n", &out_buf[3]);
    return i+3;
}

void char2dataPkt(char *in, data_pkt* pkt){
    pkt->id = in[0] | in[1] << (8*1) | in[2] << (8*2);
    printf("decrypted id: %i\n", pkt->id);
    pkt->data_len = strlen(&in[3]) > PKT_PAYLOAD_SIZE ? PKT_PAYLOAD_SIZE : strlen(&in[3]);
    int k = 3;
    while(in[k]){
        printf("%c, %i\n", in[k], in[k]);
        k++;
    }
    printf("data[3]: %s\n", &in[3]);
    pkt->data = strdup(in+3);
    printf("datalen: %i, data: %s\n", pkt->data_len, pkt->data);
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

packet prepPckt(packet pckt, char *content, int content_len){
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
        //pckt.msg[i] = i+70; 
        pckt.msg[i] = 0;

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

void pongPing(int ping_sockfd, node_t *data_queue, struct sockaddr_in addrs[], int addrs_len){
    packet pckSend;
    data_pkt pckVal;
    int payload_len = 0;
    int msg_count = 0;
    char data_char[PING_PKT_PAYLOAD_SIZE];
    while((pckVal = dequeue(&data_queue)).data_len){
        printf("--------new dequeuing--------\n");
        printf("dequeued data: %s with size %i\n", pckVal.data, pckVal.data_len);
        payload_len = dataPkt2char(pckVal, data_char);
        free(pckVal.data);
        pckSend = prepPckt(pckSend, data_char, payload_len);
        sendPing(ping_sockfd, &pckSend, addrs);
        msg_count++;
    }
    struct timeval begin, end;
    //sendPing(ping_sockfd, pck, addrs);
    // input a list of packets, send all of them quickly, afterwards only use one buffer pck and work on resending them
    while(pingLoop){
        gettimeofday(&begin, 0);
        printf("--------new ping loop iteration--------\n");
        recvPing(ping_sockfd, &pckSend);
        printf("finished receiving stuff\n");
        char2dataPkt(&pckSend.msg[RESPONSE_CONTENT_OFFSET], &pckVal);
        printf("chard2dataPkt finished...\n");
        payload_len = dataPkt2char(pckVal, data_char);
        pckSend = prepPckt(pckSend, data_char, payload_len);
        printf("prepped pck for sending \n");
        sendPing(ping_sockfd, &pckSend, &addrs[rand()%addrs_len]);
        usleep(1000000);
        gettimeofday(&end, 0);
        printf("elapsed time: %f\n", (end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec) * 1e-6);
        usleep(1000000);
    }
}

node_t* initialDataQueue(char* text){
    printf("called initial data queue \n");
    node_t *head = NULL;
    int text_len = strlen(text);
    int id = 0, strcpsize = 0;
    data_pkt tmp_pkt;
    tmp_pkt.data = (char*) malloc(sizeof(char) * PKT_PAYLOAD_SIZE + 1);
    if(tmp_pkt.data == 0){
        printf("failed to allocate memory; \n");
        return 0;
    }
    while(text_len > 0){
        printf("-------------\ntext_len: %i\n", text_len);
        printf("current leftover payload: %s\n", text);
        strcpsize =text_len >= PKT_PAYLOAD_SIZE ? PKT_PAYLOAD_SIZE  : text_len;
        printf("strcpsize: %i\n", strcpsize);
    
        strncpy(tmp_pkt.data, text, strcpsize);
        printf("tmp_pkt.data: %s\n", tmp_pkt.data);
        tmp_pkt.data_len = strcpsize;
        tmp_pkt.id = id++;
        enqueue(&head, tmp_pkt);
        text += strcpsize;
        text_len = strlen(text);
    }
    return head;
}

int main(){
    srand(0);
    int sockfd, ttl_val = 64;
    
    struct timeval tv_out;

    char *targets[] = {"localhost"}; //, "yahoo.com", "google.com", "ekg-ahrensburg.de"}; 
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


    char* data_text = "this is a long text with more than 34 letters please be long";
    node_t *data_queue = initialDataQueue(data_text);

    pongPing(sockfd, data_queue, addr_cons, target_len);
    exit(0);
}