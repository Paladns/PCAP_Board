#include "packet_parser.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#define ETH_TYPE_IP 0x0800
#define ETH_HEADER_SIZE 14

// 格式化 MAC 地址
static void format_mac(const uint8_t *mac, char *buf, int buf_size) {
    snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 格式化 IP 地址
static void format_ip(uint32_t ip, char *buf, int buf_size) {
    snprintf(buf, buf_size, "%d.%d.%d.%d",
             (ip >> 0) & 0xFF,
             (ip >> 8) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 24) & 0xFF);
}

// 解析数据包
int parse_packet(const uint8_t *packet, uint32_t length, PacketInfo *info) {
    struct eth_header *eth;
    struct ip_header *ip;
    struct tcp_header *tcp;
    struct udp_header *udp;
    uint32_t ip_header_len;
    uint32_t offset = 0;

    memset(info, 0, sizeof(PacketInfo));
    info->length = length;

    // 检查数据包长度是否足够
    if (length < ETH_HEADER_SIZE) {
        return -1;
    }

    // 解析以太网头
    eth = (struct eth_header *)packet;
    offset += ETH_HEADER_SIZE;

    format_mac(eth->src_mac, info->src_mac, sizeof(info->src_mac));
    format_mac(eth->dst_mac, info->dst_mac, sizeof(info->dst_mac));

    // 检查是否是 IP 数据包
    if (ntohs(eth->eth_type) != ETH_TYPE_IP) {
        return -1;
    }

    // 解析 IP 头
    if (length < offset + sizeof(struct ip_header)) {
        return -1;
    }
    ip = (struct ip_header *)(packet + offset);
    
    ip_header_len = (ip->ver_ihl & 0x0F) * 4;
    offset += ip_header_len;

    format_ip(ip->src_ip, info->src_ip, sizeof(info->src_ip));
    format_ip(ip->dst_ip, info->dst_ip, sizeof(info->dst_ip));
    info->protocol = ip->protocol;

    // 解析 TCP/UDP
    if (ip->protocol == 6) { // TCP
        if (length < offset + sizeof(struct tcp_header)) {
            return -1;
        }
        tcp = (struct tcp_header *)(packet + offset);
        info->src_port = ntohs(tcp->src_port);
        info->dst_port = ntohs(tcp->dst_port);
        info->tcp_flags = tcp->flags;
    } else if (ip->protocol == 17) { // UDP
        if (length < offset + sizeof(struct udp_header)) {
            return -1;
        }
        udp = (struct udp_header *)(packet + offset);
        info->src_port = ntohs(udp->src_port);
        info->dst_port = ntohs(udp->dst_port);
    }

    return 0;
}

// 获取协议名称
const char* get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "Unknown";
    }
}

// 获取 TCP 标志位字符串
void get_tcp_flags_str(uint8_t flags, char *buf, int buf_size) {
    buf[0] = '\0';
    
    if (flags & 0x02) strcat(buf, "SYN, ");
    if (flags & 0x10) strcat(buf, "ACK, ");
    if (flags & 0x01) strcat(buf, "FIN, ");
    if (flags & 0x04) strcat(buf, "RST, ");
    if (flags & 0x08) strcat(buf, "PSH, ");
    if (flags & 0x20) strcat(buf, "URG, ");
    
    // 移除末尾的 ", "
    int len = strlen(buf);
    if (len >= 2) {
        buf[len - 2] = '\0';
    }
    
    // 如果没有标志位
    if (buf[0] == '\0') {
        strncpy(buf, "-", buf_size);
    }
}