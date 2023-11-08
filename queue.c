
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct data_pkt{
    unsigned int id : 24;
    int data_len;
    char *data;
} data_pkt;

typedef struct node {
    data_pkt val;
    struct node *next;
} node_t;

extern void enqueue(node_t **head, data_pkt val) {
    node_t *new_node = malloc(sizeof(node_t));
    if (!new_node) return;
    data_pkt new_pkt = {val.id, val.data_len, strdup(val.data)};
    new_node->val = new_pkt;
    new_node->next = *head;

    *head = new_node;
}

extern data_pkt dequeue(node_t **head) {
    node_t *current, *prev = NULL;
    data_pkt retval = {-1, 0, ""};

    if (*head == NULL) return retval;

    current = *head;
    while (current->next != NULL) {
        prev = current;
        current = current->next;
    }

    retval = current->val;
    free(current);
    
    if (prev)
        prev->next = NULL;
    else
        *head = NULL;

    return retval;
}

extern void print_list(node_t *head) {
    node_t *current = head;

    while (current != NULL) {
        printf("%s\n", current->val.data);
        current = current->next;
    }
}
