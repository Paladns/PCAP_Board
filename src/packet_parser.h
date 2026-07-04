#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>

// 数据包信息结构体
typedef struct {
    int id;                     // 数据包编号
    char timestamp[64];         // 时间戳
    char src_mac[18];           // 源 MAC
    char dst_mac[18];           // 目的 MAC
    char src_ip[16];            // 源 IP
    char dst_ip[16];            // 目的 IP
    uint16_t src_port;          // 源端口
    uint16_t dst_port;          // 目的端口
    uint8_t protocol;           // 协议类型 (6=TCP, 17=UDP, 1=ICMP)
    uint8_t tcp_flags;          // TCP 标志位
    uint32_t length;            // 数据包长度
} PacketInfo;

// 以太网帧头
struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

// IP 头
struct ip_header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// TCP 头
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

// UDP 头
struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

// 解析数据包
int parse_packet(const uint8_t *packet, uint32_t length, PacketInfo *info);

// 获取协议名称
const char* get_protocol_name(uint8_t protocol);

// 获取 TCP 标志位字符串
void get_tcp_flags_str(uint8_t flags, char *buf, int buf_size);

#endif // PACKET_PARSER_H