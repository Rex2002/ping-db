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
#include <pthread.h>
#include "queue.c"


#define PING_PKT_S 64
#define PING_PKT_PAYLOAD_SIZE 36
#define PKT_ID_SIZE 3
#define PKT_PAYLOAD_SIZE 33
#define RESPONSE_CONTENT_OFFSET 20
#define PORT_NO 0 
#define RECV_TIMEOUT 1 

int pingLoop = 1;
int pck_id_counter = 0;
int readRequests[80];
int readRequestNo = 0;
pthread_mutex_t data_queue_lock;
pthread_mutex_t resp_queue_lock;
pthread_mutex_t read_request_lock;
FILE *fp;
node_t *data_queue_head = NULL;
node_t *resp_queue_head = NULL;

typedef struct ping_pkt{
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
} packet;

struct handleInputParameter{
    node_t **queue;
};

void intHandler(int dummy)
{
    fprintf(fp, "int handler called with dummy: %i \n", dummy);
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
        fprintf(fp, "invalid data packet detected: %s\n", pkt.data);
        out_buf[3] = 0;
        return 3;
    }
    fprintf(fp, "payload: %s, id1: %i, %i, %i\n", pkt.data, id1, id2, id3);
    int i;
    //strlcpy( &out_buf[3], pkt.data, pkt.data_len-1); 
    for(i = 0; i < pkt.data_len; i++){
        out_buf[i+3] = pkt.data[i];
    }
    //fprintf(fp, "outbuf %s\n", &out_buf[3]);
    return i+3;
}

void char2dataPkt(char *in, data_pkt* pkt){
    pkt->id = in[0] | in[1] << (8*1) | in[2] << (8*2);
    fprintf(fp, "decrypted id: %i\n", pkt->id);
    // todo maybe redo that
    pkt->data_len = strlen(&in[3]) > PKT_PAYLOAD_SIZE ? PKT_PAYLOAD_SIZE : strlen(&in[3]);
    pkt->data = strdup(in+3);
    fprintf(fp, "datalen: %i, data: %s\n", pkt->data_len, pkt->data);
}

void printPcktMsg(char* msg, int size){
    int i = 0;
    for(; i < 3; i++){
        fprintf(fp, "%i", msg[i]);
    }
    for(; i < size; i++){
        fprintf(fp, "%c", msg[i]);
    }
    fprintf(fp, "\n");
}

packet prepPckt(packet pckt, data_pkt data){
    char content[PING_PKT_PAYLOAD_SIZE];
    int content_len = dataPkt2char(data, content);
    fprintf(fp, "prepping with message: ");
    printPcktMsg(content, content_len);
    fprintf(fp, "message size: %i\n", content_len);
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
        fprintf(fp, "failed to send packet\n");
        fprintf(fp, "errno: %s\n", strerror(errno));
    }
    fprintf(fp, "sent message: ");
    printPcktMsg(pck->msg, sizeof(pck->msg));
}

void recvPing(int ping_sockfd, packet *pck){
    struct sockaddr_in r_addr;
    unsigned int addr_len = sizeof(r_addr);
    if(recvfrom(ping_sockfd, pck, sizeof(*pck), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0){
        fprintf(fp, "failed to receive packet \n");
        fprintf(fp, "errno: %s\n", strerror(errno));
        return;
    }
    else{
        fprintf(fp, "recv message: ");
        printPcktMsg(pck->msg, sizeof(pck->msg));
    }
}

void pongPing(int ping_sockfd, struct sockaddr_in addrs[], int addrs_len){
    packet pckSend;
    data_pkt pckVal;
    int msg_count = 0, tmp_read_req_cnt;
    while((pckVal = dequeue(&data_queue_head)).data_len){
        fprintf(fp, "--------new dequeuing--------\n");
        fprintf(fp, "dequeued data: %s with size %i\n", pckVal.data, pckVal.data_len);
        pckSend = prepPckt(pckSend, pckVal);
        free(pckVal.data);
        sendPing(ping_sockfd, &pckSend, addrs);
        msg_count++;
    }
    struct timeval begin, end;
    //sendPing(ping_sockfd, pck, addrs);
    // input a list of packets, send all of them quickly, afterwards only use one buffer pck and work on resending them
    while(pingLoop){
        gettimeofday(&begin, 0);
        fprintf(fp, "--------new ping loop iteration--------\n");
        recvPing(ping_sockfd, &pckSend);
        char2dataPkt(&pckSend.msg[RESPONSE_CONTENT_OFFSET], &pckVal);
        // add array that holds requested packets, if packet id is in that array, enqueue that packet to a response queue. 
        // add array that holds arrays that are to be deleted, if packet id is in that array, do not resend the packet
        // if id is in any array, remove id from array
        //enqueue(&data_queue, pckVal);
        pthread_mutex_lock(&read_request_lock);
        for(tmp_read_req_cnt = 0; tmp_read_req_cnt < readRequestNo; tmp_read_req_cnt++){
            fprintf(stdout, "checking for id: %i, comparing with %i\n", readRequests[tmp_read_req_cnt], pckVal.id);
            if(readRequests[tmp_read_req_cnt] == pckVal.id){
                fprintf(stdout, "found packet %i: %s\n", pckVal.id, pckVal.data);
                memmove(&readRequests[tmp_read_req_cnt], &readRequests[tmp_read_req_cnt+1], readRequestNo-(tmp_read_req_cnt+1));
                readRequests[--readRequestNo] = 0;
                break;
            }
        }
        pthread_mutex_unlock(&read_request_lock);
        pckSend = prepPckt(pckSend, pckVal);
        sendPing(ping_sockfd, &pckSend, &addrs[rand()%addrs_len]);

        pthread_mutex_lock(&data_queue_lock);
        while((pckVal = dequeue(&data_queue_head)).data_len){
            fprintf(fp, "--------new dequeuing--------\n");
            fprintf(fp, "dequeued data: %s with size %i\n", pckVal.data, pckVal.data_len);
            pckSend = prepPckt(pckSend, pckVal);
            free(pckVal.data);
            sendPing(ping_sockfd, &pckSend, addrs);
            msg_count++;
        }
        pthread_mutex_unlock(&data_queue_lock);
        usleep(1000000);
        gettimeofday(&end, 0);
        fprintf(fp, "elapsed time: %f\n", (end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec) * 1e-6);
        fflush(fp);
        usleep(1000000);
    }
}

void fillDataQueue(char* text){
    fprintf(fp, "called initial data queue \n");
    //node_t *head = NULL;
    int text_len = strlen(text);
    int strcpsize = 0;
    data_pkt tmp_pkt;
    tmp_pkt.data = (char*) malloc(sizeof(char) * PKT_PAYLOAD_SIZE + 1);
    if(tmp_pkt.data == 0){
        fprintf(fp, "failed to allocate memory; \n");
        return;
    }
    pthread_mutex_lock(&data_queue_lock);
    while(text_len > 0){
        fprintf(fp, "-------------\ntext_len: %i\n", text_len);
        fprintf(fp, "current leftover payload: %s\n", text);
        strcpsize = text_len >= PKT_PAYLOAD_SIZE ? PKT_PAYLOAD_SIZE  : text_len;
    
        strncpy(tmp_pkt.data, text, strcpsize);
        tmp_pkt.data_len = strcpsize;
        tmp_pkt.id = pck_id_counter++;
        enqueue(&data_queue_head, tmp_pkt);
        text += strcpsize;
        text_len = strlen(text);
    }
    pthread_mutex_unlock(&data_queue_lock);
    free(tmp_pkt.data);
    return;
}

void processUserInput(char *input, int str_size){
    char cmd[8];
    char str_id[4];
    int id, pos, offset;
    for(pos = 0; pos < str_size; pos++){
        if(input[pos] == ' '){
            break;
        }
        cmd[pos] = input[pos];
    }
    if(memcmp(cmd, "read", 4) == 0){
        fprintf(stdout, "recognized read command\n");
        //pos++;
        for(offset = ++pos; pos < str_size; pos++){
            if(input[pos] == ' '){
                break;
            }
            printf("character: %c\n", input[pos]);
            str_id[pos-offset] = input[pos];
            printf("copied character: %c\n", str_id[0]);
        }
        str_id[pos-offset] = '\0';

        id = atoi(str_id);
        printf("extracted str_id: %s\n", str_id);
        pthread_mutex_lock(&read_request_lock);
        readRequests[readRequestNo] = id;
        readRequestNo++;
        pthread_mutex_unlock(&read_request_lock);
    }else if(memcmp(cmd, "write", 5) == 0){
        fillDataQueue(&input[pos+1]);
        fprintf(stdout, "recognized write command\n");
    }
    else if(memcmp(cmd, "del", 3) == 0){
        fprintf(stdout, "recognized del command\n");
    }
}

void *handleUserInput(){
    char *inputBuffer;
    size_t bufsize = 64;
    size_t num_chars;
    inputBuffer = (char *)malloc(bufsize * sizeof(char));
    if(inputBuffer == NULL){
        fprintf(stderr, "failed to allocate memory for inputBuffer\n");
        free(inputBuffer);
        return NULL;
    }
    while(pingLoop){
        num_chars = getline(&inputBuffer, &bufsize, stdin);
        if(inputBuffer[num_chars-1] == '\n'){
            inputBuffer[num_chars - 1] = '\0';
            num_chars--;
        }

        //fillDataQueue(inputBuffer);
        processUserInput(inputBuffer, num_chars);
        fprintf(stdout, "\n");
        //fprintf(fp, "read %li characters in input: %s", num_chars, inputBuffer);
    }
    free(inputBuffer);
    return NULL;
}

int main(){
    fp = fopen("log.txt", "w");
    srand(0);
    int sockfd, ttl_val = 64;
    
    struct timeval tv_out;


    if (pthread_mutex_init(&data_queue_lock, NULL) != 0 
    || pthread_mutex_init(&resp_queue_lock, NULL) != 0
    || pthread_mutex_init(&read_request_lock, NULL) != 0) { 
        fprintf(fp, "\n mutex init has failed\n"); 
        strerror(errno);
        return 1; 
    } 

    char* data_text = "this is a long text with more than 34 letters please be long";
    fillDataQueue(data_text);


    pthread_t inputThread;
    pthread_create(&inputThread, NULL, handleUserInput, NULL);

    char *targets[] = {"localhost", "yahoo.com", "google.com", "ekg-ahrensburg.de"}; 
    int targets_len = sizeof(targets)/sizeof(targets[0]);
    struct sockaddr_in addr_cons[targets_len];
    prepTargets(targets, addr_cons, targets_len);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0){
        fprintf(fp, "failed to receive socket file descriptor\n");
        exit(0);
    }
    fprintf(fp, "socket file descriptor received: %d\n", sockfd);


    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0){
        fprintf(fp, "\nSetting socket options to TTL failed!\n");
        fprintf(fp, "errno: %s\n", strerror(errno));
        exit(0);
    }
    else{
        fprintf(fp, "\nSocket set to TTL..\n");
    }
 
    // setting timeout of recv setting
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   (const char*)&tv_out, sizeof tv_out);



    pongPing(sockfd, addr_cons, targets_len);
    exit(0);
}