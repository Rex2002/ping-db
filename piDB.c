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
#include "bitmap.c"


/* next steps: 
*  create bitmap of size (2^16)ids/(34byte * 8bits) = 240 to store if the indexing packets are present.
*  each indexing packet bit describes if packetId * 34 + bitNo is present.
*  when searching for a packet, first it is checked if the indexing packet
*  that should contain the packets id is present. 
*  If not it is assumed that the packet is not present. 
*  If yes, the indexing packet is checked and if the packet is present, it is then fetched
*
*
*/

#define PING_PKT_S 64
#define PING_PKT_PAYLOAD_SIZE 36
#define PKT_ID_SIZE 2
#define PKT_PAYLOAD_SIZE 34
#define RESPONSE_CONTENT_OFFSET 20
#define FIRST_DATA_PKT_ID 241
#define PORT_NO 0 
#define RECV_TIMEOUT 1 
#define BMASK   (1 << (CHAR_BIT-1))

int pingLoop = 1;
int pck_id_counter = 0;
int readRequests[80];
int readRequestNo = 0;
pthread_mutex_t data_queue_lock;
pthread_mutex_t resp_queue_lock;
pthread_mutex_t updt_queue_lock;
pthread_mutex_t read_request_lock;
FILE *fp;
node_t *data_queue_head = NULL;
node_t *resp_queue_head = NULL;
node_t *updt_queue_head = NULL;
word_t index_packets[8];



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
    fflush(fp);
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

void printbits (char value) {
    int i;
    for (i = 0; i < 8; i++) {
        printf("%d", !!((value << i) & 0x80));
    }
    printf("\n");
}

int checkBit(char value, int bitNo){
    if(bitNo > 7) {
        printf(stdout, "something went really wrong...\n");
        return 0;
    }
    printbits(value);
    for(int i = 0; i < 8; i++){
        if(i == bitNo) return ((value << i) & 0x80);
    }
    return 0;
}

int dataPkt2char(data_pkt pkt, char *out_buf){
    unsigned char id1 = (pkt.id >> (8*0)) & 0xff;
    unsigned char id2 = (pkt.id >> (8*1)) & 0xff;
    out_buf[0] = id1;
    out_buf[1] = id2;
    if(pkt.data_len > PING_PKT_PAYLOAD_SIZE - PKT_ID_SIZE){
        fprintf(fp, "invalid data packet detected: %s\n", pkt.data);
        out_buf[PKT_ID_SIZE] = 0;
        return PKT_ID_SIZE;
    }
    fprintf(fp, "id: %i-%i, payload: %s \n", id1, id2, pkt.data);
    int i;
    for(i = 0; i < pkt.data_len; i++){
        out_buf[i+PKT_ID_SIZE] = pkt.data[i];
    }
    return i+PKT_ID_SIZE;
}

void char2dataPkt(char *in, data_pkt* pkt){
    pkt->id = in[0] | in[1] << (8*1);
    fprintf(fp, "decrypted id: %i\n", pkt->id);
    // todo maybe redo that
    pkt->data_len = strlen(&in[PKT_ID_SIZE]) > PKT_PAYLOAD_SIZE ? PKT_PAYLOAD_SIZE : strlen(&in[PKT_ID_SIZE]);
    fprintf(fp, "datalen: %i\n", pkt->data_len);
    pkt->data = strdup(in+PKT_ID_SIZE);
    fflush(fp);
}

void printPcktMsg(char* msg, int size){
    int i = 0;
    for(; i < PKT_ID_SIZE; i++){
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
        fprintf(fp, "failed to receive packet. Probably recv timeout \n");
        fprintf(fp, "errno: %s\n", strerror(errno));
        return;
    }
    else{
        fprintf(fp, "recv message: ");
        printPcktMsg(pck->msg, sizeof(pck->msg));
    }
}

void pongPing(int ping_sockfd, struct sockaddr_in addrs[], int addrs_len){
    fprintf(stdout, "entering pongPing \n");
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
    fprintf(stdout, "finished dequeuing stuff\n");
    struct timeval begin, end;
    while(pingLoop){
        gettimeofday(&begin, 0);
        fprintf(fp, "--------new ping loop iteration--------\n");
        recvPing(ping_sockfd, &pckSend);
        printf(stdout, "header type: %i", pckSend.hdr.type);
        if (!(pckSend.hdr.type == 69 && pckSend.hdr.code == 0) || pckSend.hdr.un.echo.sequence == 64) {
            //fprintf(stdout, " Error..Packet received with ICMP type % d code % d\n", pckSend.hdr.type, pckSend.hdr.code);
        }
        else{
            char2dataPkt(&pckSend.msg[RESPONSE_CONTENT_OFFSET], &pckVal);
            // add array that holds requested packets, if packet id is in that array, enqueue that packet to a response queue. 
            // add array that holds arrays that are to be deleted, if packet id is in that array, do not resend the packet
            // if id is in any array, remove id from array
            //enqueue(&data_queue, pckVal);
            pthread_mutex_lock(&read_request_lock);
            for(tmp_read_req_cnt = 0; tmp_read_req_cnt < readRequestNo; tmp_read_req_cnt++){
                fprintf(stdout, "checking for id: %i, comparing with %i\n", readRequests[tmp_read_req_cnt], pckVal.id);
                if(readRequests[tmp_read_req_cnt] == pckVal.id){
                    // if a wanted packet is found, its put to the response queue;
                    pthread_mutex_lock(&resp_queue_lock);
                    enqueue(&resp_queue_head, pckVal);
                    pthread_mutex_unlock(&resp_queue_lock);
                    fprintf(stdout, "found packet %i: %s\n", pckVal.id, pckVal.data);
                    memmove(&readRequests[tmp_read_req_cnt], &readRequests[tmp_read_req_cnt+1], readRequestNo-(tmp_read_req_cnt+1));
                    readRequests[--readRequestNo] = 0;
                    break;
                }
            }
            pthread_mutex_unlock(&read_request_lock);
            pthread_mutex_lock(&updt_queue_lock);
            // todo think about what happens when id zero needs to be handled
            if(updt_queue_head != 0 && updt_queue_head->val.id == pckVal.id){
                pckSend = prepPckt(pckSend, dequeue(&updt_queue_head));
            }
            else{
                pckSend = prepPckt(pckSend, pckVal);
            }
            pthread_mutex_unlock(&updt_queue_lock);
            fprintf(stdout, "pinged ping with id %i\n", pckVal.id);
            sendPing(ping_sockfd, &pckSend, &addrs[rand()%addrs_len]);
        }
        pthread_mutex_lock(&data_queue_lock);
        while((pckVal = dequeue(&data_queue_head)).data_len){
            fprintf(fp, "--------new dequeuing--------\n");
            fprintf(fp, "dequeued data: %s with size %i\n", pckVal.data, pckVal.data_len);
            pckSend = prepPckt(pckSend, pckVal);
            sendPing(ping_sockfd, &pckSend, addrs);
            free(pckVal.data);
            msg_count++;
        }
        pthread_mutex_unlock(&data_queue_lock);
        usleep(1000000);
        gettimeofday(&end, 0);
        fprintf(fp, "elapsed time: %f\n", (end.tv_sec - begin.tv_sec) + (end.tv_usec - begin.tv_usec) * 1e-6);
        fflush(fp);
        usleep(1000000);
        //free(pckVal.data);
    }
}

void createPacket(int id, char* data, int content_len){
    data_pkt pkt;
    pkt.data = data;
    pkt.data_len = content_len;
    pkt.id = id;
    pthread_mutex_lock(&data_queue_lock);
    enqueue(&data_queue_head, pkt);
    pthread_mutex_unlock(&data_queue_lock);
}

// method to update an existing packet with given id and data
void updatePacket(int id, data_pkt data){
    data.id = id;
    pthread_mutex_lock(&updt_queue_lock);
    enqueue(&updt_queue_head, data);
    pthread_mutex_unlock(&updt_queue_lock);
}

// method used to create a new index packet where the 0th index is set to 1;
void createIndexPacket(int idx_id){
    printf("creating index packet with id: %i\n", idx_id );
    set_bit(index_packets, idx_id);
    char data = (char) 0 | (char) 0x80;
    createPacket(idx_id, &data, 1);
}

int getNextId(){
    int id = -1;
    int index_pck_id = 1;
    int smallest_empty_index_pck = -1;
    data_pkt pck;
    // checking if an index packet that has "space" for another packet exists (i.e. is not 255 at each byte)
    for(; index_pck_id < FIRST_DATA_PKT_ID; index_pck_id++){
        // check if index packet no. index_pck_id exists
        // if so, load the packet and check, if there is a byte that is not "full"
        if(get_bit(index_packets, index_pck_id)){
            fprintf(stdout, "bit %i is present\n", index_pck_id);
            pthread_mutex_lock(&read_request_lock);
            readRequests[readRequestNo] = index_pck_id;
            readRequestNo++;
            pthread_mutex_unlock(&read_request_lock);
            while(1){
                pthread_mutex_lock(&resp_queue_lock);
                if(resp_queue_head && (resp_queue_head->val.data_len || resp_queue_head->val.id)){
                    break;
                }
                pthread_mutex_unlock(&resp_queue_lock);
                usleep(1000000);
            }
            pck = dequeue(&resp_queue_head);
            pthread_mutex_unlock(&resp_queue_lock);

            for(unsigned char k = 0; k < pck.data_len; k ++){
                if(pck.data[k] != -127){
                    for(id = 0; id<8; id++){
                        if(pck.data[k] & (1 << (7 - id))) fprintf(stdout, "1\n"); 
                        else fprintf(stdout, "0\n");
                        if(!(pck.data[k] & (1 << (7 - id)))){
                            pck.data[k] = pck.data[k] | (1 << ( 7 -id) );
                            break;
                        }
                    }
                    id += k*8;
                    break;
                }
            }
            if(id != -1){
                id += index_pck_id*8*PKT_PAYLOAD_SIZE;
                break;
            }
        }
        else if(smallest_empty_index_pck == -1){
            smallest_empty_index_pck = index_pck_id;
        }
    }
    if(id != -1){
        updatePacket(index_pck_id, pck);
        return id;
    }
    else if (smallest_empty_index_pck != -1){
        id = smallest_empty_index_pck*8*PKT_PAYLOAD_SIZE;
        createIndexPacket(smallest_empty_index_pck);
        return id;
    }
    else {
        return -1;
    }  
}

void writePacket(char *content, int content_len){
    int id = getNextId();
    if(id == -1){
        fprintf(stdout, "could not write packet %i. Database is full", id);
        return;
    }
    fprintf(stdout, "acquired packet id %i, writing content %.*s\n", id, content_len, content);
    createPacket(id, content, content_len);
}

void fillDataQueue(char* data){
    fprintf(fp, "filling data queue with: %s \n", data);
    int data_len = strlen(data);
    int strcpsize = 0;
    data_pkt tmp_pkt;
    tmp_pkt.data = (char*) malloc(sizeof(char) * PKT_PAYLOAD_SIZE + 1);
    if(tmp_pkt.data == 0){
        fprintf(fp, "failed to allocate memory; \n");
        return;
    }
    //pthread_mutex_lock(&data_queue_lock);
    char toWrite[PKT_PAYLOAD_SIZE];
    while(data_len > 0){
        strcpsize = data_len >= PKT_PAYLOAD_SIZE ? PKT_PAYLOAD_SIZE  : data_len;
    
        //strncpy(tmp_pkt.data, data, strcpsize);
        //tmp_pkt.data_len = strcpsize;
        //tmp_pkt.id = pck_id_counter++;
        strncpy(toWrite, data, strcpsize);
        writePacket(toWrite, strcpsize);
        //enqueue(&data_queue_head, tmp_pkt);
        data += strcpsize;
        data_len = strlen(data);
    }
    //pthread_mutex_unlock(&data_queue_lock);
    free(tmp_pkt.data);
    return;
}

int checkPacketId(int packetId){
    data_pkt pck;
    int idx_pckt_id = packetId/(PKT_PAYLOAD_SIZE * 8);
    if(!get_bit(index_packets, idx_pckt_id)){
        return 0;
    }
    fprintf(stdout, "searching for index packet %i\n", idx_pckt_id);
    pthread_mutex_lock(&read_request_lock);
    readRequests[readRequestNo] = idx_pckt_id;
    readRequestNo++;
    pthread_mutex_unlock(&read_request_lock);
    while(1){
        pthread_mutex_lock(&resp_queue_lock);
        if(resp_queue_head && (resp_queue_head->val.data_len || resp_queue_head->val.id)){
            break;
        }
        pthread_mutex_unlock(&resp_queue_lock);
        usleep(1000000);
    }
    pck = dequeue(&resp_queue_head);
    pthread_mutex_unlock(&resp_queue_lock);
    fprintf(stdout, "starting to print idx packet: \n");
    fprintf(stdout, "idx pck length: %i, index packet id: %i \n", pck.data_len, pck.id);
    int byteNo = (packetId%34)/8;
    int bitNo = packetId%(34*8);
    if(byteNo >= pck.data_len) return 0;
    int ret = checkBit(pck.data[byteNo], bitNo);
    free(pck.data);
    pck.id = 0; pck.data_len = 0;
    return ret;
    
}

void readPacket(int packetId){
    if(!checkPacketId(packetId)){
        fprintf(stdout, "the packet %i does not exist\n", packetId);
        return;
    }    
    pthread_mutex_lock(&read_request_lock);
    readRequests[readRequestNo] = packetId;
    readRequestNo++;
    pthread_mutex_unlock(&read_request_lock);
    while(1){
        pthread_mutex_lock(&resp_queue_lock);
        if(resp_queue_head && (resp_queue_head->val.data_len || resp_queue_head->val.id)){
            break;
        }
        pthread_mutex_unlock(&resp_queue_lock);
        usleep(1000000);
    }
    dequeue(&resp_queue_head);
    fprintf(stdout, "packet content should have been printed above\n");
    pthread_mutex_unlock(&resp_queue_lock);

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
        for(offset = ++pos; pos < str_size; pos++){
            if(input[pos] == ' '){
                break;
            }
            str_id[pos-offset] = input[pos];
        }
        str_id[pos-offset] = '\0';

        id = atoi(str_id);
        readPacket(id);
    }else if(memcmp(cmd, "write", 5) == 0){
        //writePacket(&input[pos+1]);
        fprintf(stdout, "recognized write command\n");
        fillDataQueue(&input[pos+1]);
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
    //fillDataQueue(data_text);


    pthread_t inputThread;
    pthread_create(&inputThread, NULL, handleUserInput, NULL);

    char *targets[] = {"localhost"};//, "yahoo.com", "google.com", "ekg-ahrensburg.de"}; 
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


    fflush(fp);
    pongPing(sockfd, addr_cons, targets_len);
    exit(0);
}