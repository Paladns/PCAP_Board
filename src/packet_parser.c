#include "packet_parser.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <winsock2.h>


// 以太网头
struct eth_header {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

// IPv4 头
struct ip_header {
    u_char version_ihl;
    u_char tos;
    u_short total_len;
    u_short id;
    u_short frag_off;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    struct in_addr src_addr;
    struct in_addr dest_addr;
};

// TCP 头
struct tcp_header {
    u_short src_port;
    u_short dest_port;
    u_int seq_num;
    u_int ack_num;
    u_char data_offset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
};

// UDP 头
struct udp_header {
    u_short src_port;
    u_short dest_port;
    u_short len;
    u_short checksum;
};


const char* get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "Other";
    }
}

/**
 * 解析单个数据包
 * @param packet 指向数据包原始数据
 * @param len 数据包长度
 * @param info 输出参数，解析结果存储在这里
 * @return 成功返回 0，失败返回 -1
 */
int parse_packet(const u_char *packet, uint32_t len, PacketInfo *info) {
    memset(info, 0, sizeof(PacketInfo));
    info->length = len;
    struct eth_header *eth = (struct eth_header *)packet;
    u_int eth_len = sizeof(struct eth_header);
    if (len < eth_len) return -1;
    u_short eth_type = ntohs(eth->type);
    if (eth_type != 0x0800) {
        info->protocol = 0xFF;
        return 0;
    }
    struct ip_header *ip = (struct ip_header *)(packet + eth_len);
    u_int ip_len = (ip->version_ihl & 0x0F) * 4;
    if (len < eth_len + ip_len) return -1;
    strncpy(info->src_ip, inet_ntoa(ip->src_addr), 15);
    strncpy(info->dst_ip, inet_ntoa(ip->dest_addr), 15);
    info->protocol = ip->protocol;
    info->src_port = 0;
    info->dst_port = 0;
    info->tcp_flags = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcp_header *tcp = (struct tcp_header *)((u_char *)ip + ip_len);
        if (len >= eth_len + ip_len + sizeof(struct tcp_header)) {
            info->src_port = ntohs(tcp->src_port);
            info->dst_port = ntohs(tcp->dest_port);
            info->tcp_flags = tcp->flags;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udp_header *udp = (struct udp_header *)((u_char *)ip + ip_len);
        if (len >= eth_len + ip_len + sizeof(struct udp_header)) {
            info->src_port = ntohs(udp->src_port);
            info->dst_port = ntohs(udp->dest_port);
        }
    }
    return 0;
}

//将 TCP 标志位转换为可读字符串
void get_tcp_flags_str(uint8_t flags, char *buf, int buf_size) {
    const char *names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    int bits[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    int first = 1;
    buf[0] = '\0';
    for (int i = 0; i < 8; i++) {
        if (flags & bits[i]) {
            if (!first) {
                strncat(buf, ", ", buf_size - strlen(buf) - 1);
            }
            strncat(buf, names[i], buf_size - strlen(buf) - 1);
            first = 0;
        }
    }
    if (first) {
        strncpy(buf, "None", buf_size);
    }
}