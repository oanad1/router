#include "skel.h"
#include "queue.h"
#include "list.h"
#include "utils.c"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>


/*A node in the ARP table structure */
typedef struct ARPEntry {
	uint32_t ip;                    
	uint8_t mac[6];
    struct ARPEntry* next;
} ARPEntry;

/*A routing table entry associated with the last node of each address */
typedef struct RTableEntry {

   uint32_t next_hop;        
   uint32_t mask;             
   unsigned int interface;
   struct RTableEntry *next;

} RTableEntry;

/*A node in the trie which holds the routing table */
typedef struct TNode {

    struct TNode *children[2];
    RTableEntry* entries;
    uint32_t prefix;

} TNode;

/*A node in a hash map which keeps all queued packages by their respective ip */
typedef struct PQNode{
     
     uint32_t ip;
     queue packets;
     struct PQNode* next;

} PQNode;


struct ARPEntry *arp_table;
PQNode *packet_queue;




/*Adds a new entry to the ARP table */
void add_arp_entry (u_char mac_address[6], uint32_t ip_address) {

    ARPEntry *new = (ARPEntry*) malloc(sizeof(ARPEntry));
    new->ip = ip_address;
    memcpy(new->mac, mac_address,6);
    new->next = NULL;

     if(arp_table == NULL){
        arp_table = new;
        return;
     }

     ARPEntry *temp = arp_table;

     while(temp->next != NULL)
           temp = temp->next;

    temp->next = new;
}

/*Searches for an entry in the ARP table associated with the given IP */
ARPEntry* search_arp_entry(uint32_t ip_address){
     
     ARPEntry *temp = arp_table;

     if(temp == NULL)
        return NULL;

     while(temp != NULL && (temp->ip != ip_address))
           temp = temp->next;
     
     if(temp != NULL && temp->ip == ip_address)
        return temp;
    
    return NULL;
}


/*Adds a new entry to the hashmap of queued packages */
void add_packet_queue(packet* m, uint32_t ip){

    if(packet_queue == NULL){
       PQNode *new = (PQNode*) malloc(sizeof(PQNode));
       new->ip = ip;
       new->packets = queue_create();
       queue_enq(new->packets, m);
       new->next = NULL;
       packet_queue = new;
       return;
    }

    PQNode *temp = packet_queue;
    
    while(temp->next != NULL && temp->ip != ip)
          temp = temp->next;

    if(temp->ip == ip){

        queue_enq(temp->packets, m);

    } else {

       PQNode *new = (PQNode*) malloc(sizeof(PQNode));
       new->ip = ip;
       new->packets = queue_create();
       queue_enq(new->packets, m);
       new->next = NULL;
       temp->next = new;
    }
}

/*Removes a given entry from the hashmap of queued packages */
void free_queued_packets (PQNode* node){
    if(packet_queue == NULL) return;

    PQNode *current = packet_queue;
    PQNode *prev = NULL;

    while(current != NULL && current != node){
        prev = current;
        current = current->next;
    }

    if(prev != NULL && current != NULL && current == node){
        prev->next = current->next;
        free(current);
    }
}


/*Sends all queued packages associated with the given IP */
void send_queued_package(TNode* root, uint32_t ip){ 

    if(packet_queue == NULL) return;

    PQNode *temp = packet_queue; 

    while(temp != NULL && temp->ip != ip)
          temp = temp->next;
   
    if(temp != NULL && temp->ip == ip) {

        ARPEntry *entry = search_arp_entry(ip);

        while(entry != NULL && !queue_empty(temp->packets)){

        packet *p = (packet*) queue_deq(temp->packets);
        struct ether_header *eth_hdr = (struct ether_header *)&p->payload;
    
        memcpy(eth_hdr->ether_dhost, entry->mac, 6); 
        send_packet(p->interface, p); 
        entry = entry->next; 
        }

        free_queued_packets(temp);
    }
}


/*Creates a new node in the prefix trie */
 TNode *create_node() { 
    TNode *new_node = NULL; 
  
    new_node = (TNode*) malloc(sizeof(TNode)); 
  
    if (new_node == NULL) 
        return NULL;
  
    new_node->children[0] = NULL; 
    new_node->children[1] = NULL; 
    new_node->entries = NULL;
    new_node->prefix = 1;
 
    return new_node; 
} 

/*Adds a new routing table entry associated with the given prefix */
void add_entry (TNode *node, RTableEntry* entry){

    if(node->entries == NULL){
       node->entries = entry;
       return;
    }

    if(node->entries->mask < entry->mask){
           entry->next = node->entries;
           node->entries = entry;
           return;
    }

    RTableEntry *temp = node->entries;

    while(temp->next != NULL && temp->next->mask > entry->mask)
          temp = temp->next;

    if(temp->next == NULL) {
          temp->next = entry;
          return;
    }

    entry->next = temp->next;
    temp->next = entry;
}

/*Adds a new prefix to the prefix trie */
void insert(TNode *root, uint32_t address, RTableEntry* entry) { 

    int idx; 
    TNode *temp = root; 
    uint32_t bit_check = 1;
  
    for (int i = 0; i < 32; i++) { 

        idx = (address >> (31 - i)) & bit_check; 
        
        if (temp->children[idx] == NULL) {
            temp->children[idx] = create_node(); 
        }
        
        if(i < 31)
        temp = temp->children[idx]; 
    } 
    
    temp->prefix = address;
    add_entry(temp,entry);
} 


/*Searches for a prefix in the prefix trie */
TNode* search_prefix(TNode *root, uint32_t address) { 

    int idx; 
    TNode *temp = root; 
	uint32_t bit_check = 1;
  
    for (int i = 0; i < 32; i++) { 

        idx = (address >> (31 - i)) & bit_check;   

        if (temp->children[idx] == NULL) {

            if(idx == 1 && temp->children[0]) {
                
                if(i < 31)
                temp =  temp->children[0];

            } else if(!temp->entries) return NULL;

        } else {
                if(i < 31)
                temp = temp->children[idx]; 
        }
    } 

    return temp; 
} 

/*Reads the routing table entries from file and creates a prefix trie */
TNode* parse_rtable(){
	FILE *in = fopen("rtable.txt", "r");
	char prefix[20], next_hop[20], mask[20];
	int interface;
    RTableEntry *entry = NULL;
    TNode *root = create_node();

	if (!in) {   
              printf("Error! Could not open file\n"); 
              return NULL;
            } 
	
	while(fscanf(in, "%s %s %s %d\n", prefix, next_hop, mask, &interface) != EOF){
           
          entry = (RTableEntry *) malloc (sizeof(RTableEntry));
		  entry->next_hop = inet_addr(next_hop);
		  entry->mask = inet_addr(mask);
		  entry->interface = interface;
          entry->next = NULL;

          insert(root, ntohl(inet_addr(prefix)), entry);
	}

    fclose(in);
    return root;
}