//
//  main.m
//  gta5_players
//
//  Created by Ethan Arbuckle on 3/14/16.
//  Copyright © 2016 Ethan Arbuckle. All rights reserved.
//

#import <Foundation/Foundation.h>
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void filterPacket(const u_char * , int, char* ip);

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
};

NSMutableDictionary *savedNamed;

struct ethhdr {
    unsigned char	h_dest[6];	/* destination eth addr	*/
    unsigned char	h_source[6];	/* source ether addr	*/
    unsigned short	h_proto;		/* packet type ID field	*/
} __attribute__((packed));

int main()
{
    
    savedNamed = [[NSMutableDictionary alloc] init];
    
    pcap_t *handle = pcap_open_live("en0" , 65536 , 1 , 0 , NULL);
    pcap_loop(handle , -1 , process_packet , NULL);
    
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {

    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    if (iph->protocol == 17) {
        
        struct udphdr *udph = (struct udphdr*)(buffer + (iph->ihl * 4) + sizeof(struct ethhdr));
        
        int header_size =  sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof udph;
        
        struct sockaddr_in destination;
        memset(&destination, 0, sizeof(destination));
        destination.sin_addr.s_addr = iph->daddr;
        
        if (udph->uh_ulen == 26112 && udph->uh_sport == 23076) {
            filterPacket(buffer + header_size, header->len - header_size, inet_ntoa(destination.sin_addr));
        }

    }
}

void filterPacket(const u_char * data , int Size, char* ip)
{
    NSMutableString *nameData = [[NSMutableString alloc] init];
    
    for (int i = 0; i < Size - 16; i++) {
        if (data[i] >= 32 && data[i] <= 128)
            [nameData appendFormat:@"%c", (unsigned char)data[i]];
    }
    
    if ([nameData rangeOfString:@"ethanarbuckle"].location != NSNotFound && [nameData length] < 50 && ![[[NSString stringWithFormat:@"%s", ip] substringWithRange:NSMakeRange(0, 4)] isEqualToString:@"192."]) {
        [nameData replaceOccurrencesOfString:@"ethanarbuckle" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, [nameData length])];
        NSArray *idents = @[ @"usps", @"frps", @"caps", @"beps", @"hkps", @"aups", @"deps", @"nlps", @"myps", @"mxps", @"brps", @"mtps", @"gbps", @"krps", @"fips"];
        
        for (NSString *identifier in idents) {
            while ([nameData rangeOfString:identifier].location != NSNotFound) {
                [nameData replaceCharactersInRange:NSMakeRange([nameData rangeOfString:identifier].location - 2, 7) withString:@""];
            }
        }
        
        [nameData replaceOccurrencesOfString:@"\\" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, [nameData length])];
        
        if (![savedNamed valueForKey:[NSString stringWithFormat:@"%s", ip]]) {
            
            [savedNamed setValue:nameData forKey:[NSString stringWithFormat:@"%s", ip]];
            NSLog(@"%@ :: %s", nameData, ip);
        }
        
    }
}
