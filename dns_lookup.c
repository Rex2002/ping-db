#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>


#define PORT_NO 0


extern char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con){
    printf("Resolving DNS..\n");
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

extern void prepTargets (char *targets[], struct sockaddr_in* addrs, int targets_len){
    char *ip_addrs[targets_len];
    for(int i = 0; i < targets_len; i++){
        ip_addrs[i] = dns_lookup(targets[i], &(addrs[i]));
        printf("resolved %s to %s\n", targets[i], *(ip_addrs + i));
    }
}