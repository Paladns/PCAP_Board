#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <pcap.h>

/**
 * 存储解析后的数据包基本信息
 */
typedef struct {
    char timestamp[64];    // 时间戳字符串
    char src_ip[16];        // 源 IP 地址
    char dst_ip[16];        // 目的 IP 地址
    uint16_t src_port;       // 源端口
    uint16_t dst_port;       // 目的端口
    uint8_t protocol;       // 协议类型
    uint32_t length;         // 包长度
    uint8_t tcp_flags;     // TCP 标志位
} PacketInfo;

/**
 * 获取协议名称字符串
 * @param protocol 协议号
 * @return 对应协议的名称字符串（如 "TCP", "UDP"）
 */
const char* get_protocol_name(uint8_t protocol);

/**
 * 解析单个数据包
 * @param packet 指向数据包原始数据
 * @param len 数据包长度
 * @param info 输出参数，解析结果存储在这里
 * @return 成功返回 0，失败返回 -1
 */
int parse_packet(const u_char *packet, uint32_t len, PacketInfo *info);

/**
 * 将 TCP 标志位转换为可读字符串
 * @param flags TCP 标志位
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 */
void get_tcp_flags_str(uint8_t flags, char *buf, int buf_size);

#endif