#include "skel.h"
#include "helpers.c"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>



/*Searches the routing table for the prefix associated with the given IP */
RTableEntry* get_best_route (TNode* root, uint32_t dest_ip) {
    
    TNode* node = search_prefix(root, ntohl(dest_ip));

    if(node == NULL){
       //No route found
       return NULL; 

    } else {
        RTableEntry* temp = node->entries;

        while(temp != NULL) {

            //Check if mask & dest_address == prefix
            if ((ntohl(temp->mask) & ntohl(dest_ip)) ==  node->prefix){
                return temp;
            }
            temp = temp->next;
        }
    }
       //No route found
       return NULL; 
}


/*Sends an ARP request packet */
void send_arp_request(RTableEntry* best_route){


        //Create an ARP request packet
        packet arp_req;
        arp_req.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

        //Complete the Ethernet header for the ARP request
        struct ether_header *eth_req = (struct ether_header *)arp_req.payload;

        //Complete the source MAC address
        uint8_t *source_mac = malloc(6*sizeof(uint8_t));
        get_interface_mac(best_route->interface, source_mac);
        memcpy(eth_req->ether_shost, source_mac, 6);

        //Complete the destination MAC address
        memset(eth_req->ether_dhost, 255, 6);

        //Complete the type
        eth_req->ether_type = htons(0x0806);


        //Complete the ARP header for the ARP request
        struct ether_arp *arp_eth_req = (struct ether_arp *)(arp_req.payload + sizeof(struct ether_header));
        arp_eth_req->arp_hrd = htons(1);
        arp_eth_req->arp_pro = htons(0x0800);
        arp_eth_req->arp_hln = htons(6) >> 8;
        arp_eth_req->arp_pln = htons(4) >> 8;
        arp_eth_req->arp_op = htons(1);

        //Complete the source and target MAC
        memcpy(arp_eth_req->arp_sha, source_mac, 6);
        memset(arp_eth_req->arp_tha, 0, 6);

        //Complete the source and target IP
        uint32_t spa = inet_addr(get_interface_ip (best_route->interface));
        memcpy(arp_eth_req->arp_spa, &spa, 4);
        memcpy(arp_eth_req->arp_tpa, &best_route->next_hop, 4);

        //Send the request
        send_packet(best_route->interface, &arp_req);
}


/*Sends a 'destination unreachable' packet */
 void send_dest_unreach(packet m){
         
        //Create a new packet
        packet d_unreach;
        d_unreach.interface = m.interface;
        d_unreach.len  = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr); 

        //Complete the Ethernet header
        struct ether_header *d_unreach_eth = (struct ether_header *)d_unreach.payload;
        struct ether_header *eth_hdr = (struct ether_header *)m.payload;

        //Swap the original source and destination MAC 
        memcpy(d_unreach_eth ->ether_shost, eth_hdr->ether_dhost, 6);         
        memcpy(d_unreach_eth ->ether_dhost, eth_hdr->ether_shost, 6);
        d_unreach_eth ->ether_type = htons(0x0800);

        //Complete the IP header
        struct iphdr *d_unreach_ip = (struct iphdr *)(d_unreach.payload + sizeof(struct ether_header));
        struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));  

        d_unreach_ip->version = 4;
        d_unreach_ip->ihl = 5;
        d_unreach_ip->tos = 0;
        d_unreach_ip->ttl = 64;
        d_unreach_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
        d_unreach_ip->id = htons(1);
        d_unreach_ip->frag_off = 0;
        d_unreach_ip->protocol = IPPROTO_ICMP;
        
        //Swap the original source and destination IP
        d_unreach_ip->saddr = ip_hdr->daddr;
        d_unreach_ip->daddr = ip_hdr->saddr;

        //Recalculate the IP checksum
        d_unreach_ip->check = 0;
        d_unreach_ip->check = checksum(d_unreach_ip,sizeof(struct iphdr));

        //Complete the ICMP header
        struct icmphdr *d_unreach_icmp = (struct icmphdr *)(d_unreach.payload + sizeof(struct ether_header) + sizeof(struct iphdr)); 
        d_unreach_icmp->type = 3;
        d_unreach_icmp->code = 0;
        
        //Recalculate the ICMP checksum
        d_unreach_icmp->checksum = 0;
        d_unreach_icmp->checksum = checksum( d_unreach_icmp,sizeof(struct icmphdr));

        //Send the 'destination unreachable' packet
        send_packet(d_unreach.interface, &d_unreach);
  }



int main(int argc, char *argv[])
{
	packet m;
	int rc;
	init();

    //Parse the routing table 
	TNode *root = parse_rtable();
    DIE(root == NULL, "memory");
    arp_table = NULL;

      while (1) {
        
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
        uint16_t type;

        //Check packet type
        switch (ntohs(eth_hdr->ether_type)) {
        
        //ARP type
        case 0x0806:
            type = 0;
            struct ether_arp *arp_ethr = (struct ether_arp *)(m.payload + sizeof(struct ether_header));
            type = ntohs(arp_ethr->arp_op);
            
            int target_ip;                                  
            int source_ip;
            memcpy(&target_ip, arp_ethr->arp_tpa, 4);
            memcpy(&source_ip, arp_ethr->arp_spa, 4);

            switch (type) {
            
            case ARPOP_REQUEST:

                //Check if the ARP request is destined for the router
                if(inet_addr(get_interface_ip (m.interface)) == target_ip){
                   
                   //Create an ARP reply packet
                   packet arp_reply;
                   arp_reply.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

                   //Complete the Ethernet header for the ARP reply
		           struct ether_header *eth_reply = (struct ether_header *)arp_reply.payload;
                   
                   //Complete the source MAC address
                   uint8_t *source_mac = malloc(6*sizeof(uint8_t));
                   get_interface_mac(m.interface, source_mac);
                   memcpy(eth_reply->ether_shost, source_mac, 6);
                      
                   //Complete the destination MAC address
                   memcpy(eth_reply->ether_dhost, arp_ethr->arp_sha, 6);
                   
                   //Complete the type
                   eth_reply->ether_type = htons(0x0806);


                   //Complete the ARP header for the ARP reply
                   struct ether_arp *arp_eth_reply = (struct ether_arp *)(arp_reply.payload + sizeof(struct ether_header));
                   arp_eth_reply->arp_hrd = htons(1);
                   arp_eth_reply->arp_pro = htons(0x0800);
                   arp_eth_reply->arp_hln = htons(6) >> 8;
                   arp_eth_reply->arp_pln = htons(4) >> 8;
                   arp_eth_reply->arp_op = htons(2);

                   //Complete the source and target MAC
                   memcpy(arp_eth_reply->arp_sha, source_mac, 6);
                   memcpy(arp_eth_reply->arp_tha, arp_ethr->arp_sha, 6);
                   
                   //Complete the source and target IP
                   memcpy(arp_eth_reply->arp_spa, arp_ethr->arp_tpa, 4);
                   memcpy(arp_eth_reply->arp_tpa, arp_ethr->arp_spa, 4);

                   //Send the reply and move on to the next packet
                   send_packet(m.interface, &arp_reply);
                   continue;

                } else {
                   //Dismiss an ARP request not destined for the router
                   continue;
                }
                break;

            case ARPOP_REPLY:
                //The packet is an ARP reply - add an ARP entry for this MAC address
                add_arp_entry(arp_ethr->arp_sha, source_ip);

                //Send any queued packages associated with this IP 
                send_queued_package(root,source_ip);
                continue;
                break;
            
            default:
                break;
            }

            break;

        case 0x0800:
            type = 0;
            struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

            //If TTL <= 1, drop the packet and send a 'time exceeded' packet
            if(ip_hdr->ttl <= 1){

                //Create a new icmp packet
                packet ptimeout;
                ptimeout.interface = m.interface;
                ptimeout.len  = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr); 

                //Complete the Ethernet header
                struct ether_header *ptimeout_eth = (struct ether_header *)ptimeout.payload;

                //Swap the original packet's source and destination MAC
                memcpy(ptimeout_eth->ether_shost, eth_hdr->ether_dhost, 6);         
                memcpy(ptimeout_eth->ether_dhost, eth_hdr->ether_shost, 6);
                ptimeout_eth->ether_type = htons(0x0800);

                //Complete the IP header
                struct iphdr *ptimeout_ip = (struct iphdr *)(ptimeout.payload + sizeof(struct ether_header));       
                ptimeout_ip->version = 4;
                ptimeout_ip->ihl = 5;
                ptimeout_ip->tos = 0;
                ptimeout_ip->ttl = 64;
                ptimeout_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
                ptimeout_ip->id = htons(1);
                ptimeout_ip->frag_off = 0;
                ptimeout_ip->protocol = IPPROTO_ICMP;

                //Swap the original packet's source and destination IP
                ptimeout_ip->saddr = ip_hdr->daddr;
                ptimeout_ip->daddr = ip_hdr->saddr;

                //Recalculate the IP checksum 
                ptimeout_ip->check = 0;
	            ptimeout_ip->check = checksum(ptimeout_ip,sizeof(struct iphdr));

                //Complete the ICMP header
                struct icmphdr *ptimeout_icmp = (struct icmphdr *)(ptimeout.payload + sizeof(struct ether_header) + sizeof(struct iphdr)); 
                ptimeout_icmp->type = 11;
                ptimeout_icmp->code = 0;

                //Recalculate the ICMP checksum
                ptimeout_icmp->checksum = 0;
                ptimeout_icmp->checksum = checksum(ptimeout_icmp,sizeof(struct icmphdr));
                
                //Send the 'time exceeded' packet
                send_packet(ptimeout.interface, &ptimeout);
		        continue;

            }
            
            //If the checksum is wrong, drop the packet 
            int check = ip_hdr->check;
            ip_hdr->check = 0;

            if(check != checksum(ip_hdr, sizeof(struct iphdr))) {
                continue;
            }
            ip_hdr->check = check;

            
            //If the packet is an ICMP Echo Request, check if it's a ping for the router
            if(ip_hdr->protocol == IPPROTO_ICMP){

        
                 struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr)); 

                if(icmp_hdr->type == 8  &&  ip_hdr->daddr == inet_addr(get_interface_ip (m.interface))){
                        
                     //Search for a route in the routing table back to the sender
                     RTableEntry* best_route = get_best_route(root, ip_hdr->saddr);

                     //Send destination unreachable if no route is found
                     if(best_route == NULL){
                       send_dest_unreach(m);
                       continue;
                     }             
                      
                      //Swap the source and destination IP
                      uint32_t source_ip = ip_hdr->saddr;
                      ip_hdr->saddr = ip_hdr->daddr;
                      ip_hdr->daddr = source_ip;         
                      
                      //Recalculate the checksum and modify TTL
                      ip_hdr->ttl = 64;
                      ip_hdr->check = 0;
                      ip_hdr->check = checksum(ip_hdr,sizeof(struct iphdr));

                      //Modify the ICMP type and recalculate the ICMP checksum
                      icmp_hdr->type = 0;
                      icmp_hdr->code = 0;
                      icmp_hdr->checksum = 0;
	                  icmp_hdr->checksum = checksum(icmp_hdr,sizeof(struct icmphdr));
                      
                      //Get the MAC address for the best route interface 
                      uint8_t *source_mac = malloc(6*sizeof(uint8_t));
                      get_interface_mac(best_route->interface, source_mac);  
                      memcpy(eth_hdr->ether_shost, source_mac, 6);

                     //Get the MAC for the next hop
                     ARPEntry* dest_arp = search_arp_entry(best_route->next_hop);

                     if(dest_arp == NULL) {
                         
                        //If no match is found in the ARP table, send an ARP request
                        send_arp_request(best_route);

                        //Add the echo reply to a queue to send when the destination MAC is known 
                        packet* new = malloc(sizeof(packet));
                        memcpy(new, &m, sizeof(packet));
                        new->interface = m.interface;
                        new->len = m.len;
                        add_packet_queue(new, best_route->next_hop);

                        //Move on to the next packet
                        continue;

                     } else {
                        //If a match is found, copy the MAC address for the destination host
                        memcpy(eth_hdr->ether_dhost, dest_arp->mac, 6);

                        //Send the ICMP echo reply
                        send_packet(best_route->interface, &m);

                        //Move on to the next packet
                        continue;
                     }
                }    
            }

            //Search for a route in the routing table
            RTableEntry* best_route = get_best_route(root, ip_hdr->daddr);

            //Send destination unreachable if no route is found
            if(best_route == NULL){           
                send_dest_unreach(m);
                continue;
            }

            //Get the MAC for the next hop
            ARPEntry* dest_arp = search_arp_entry(best_route->next_hop);
            
            //Check if there is a match in the ARP table
            if(dest_arp == NULL) {
                  
                   //If there is no match, send an ARP request
                   send_arp_request(best_route);
                   
                   //Update the source MAC of the packet 
                   uint8_t *source_mac = malloc(6*sizeof(uint8_t));
                   get_interface_mac(best_route->interface, source_mac);
                   memcpy(eth_hdr->ether_shost, source_mac, 6); 

                  //Decrement TTL and update checksum 
                  ip_hdr->ttl--;
                  ip_hdr->check = 0;
                  ip_hdr->check = checksum(ip_hdr,sizeof(struct iphdr));
                  
                  //Add the packet to a queue to send when the destination MAC is known 
                  packet* new = malloc(sizeof(packet));
                  memcpy(new, &m, sizeof(packet));
                  new->interface = best_route->interface;
                  new->len = m.len;
                  add_packet_queue(new, best_route->next_hop);

                  //Move on to the next packet
                  continue; 


            } else {

                //Modify source and destination MAC from the original package
                uint8_t *source_mac = malloc(6*sizeof(uint8_t));
                get_interface_mac(best_route->interface, source_mac);

                memcpy(eth_hdr->ether_shost, source_mac, 6);         
                memcpy(eth_hdr->ether_dhost, dest_arp->mac, 6);
  
                //Update the checksum and decrement TTL
                ip_hdr->ttl--;
                ip_hdr->check = 0;
                ip_hdr->check = checksum(ip_hdr,sizeof(struct iphdr));
                
                //Forward the packet 
                send_packet(best_route->interface, &m); 
            } 

            break; 
        
        default:
            break;
        }

    }
}
