#ifndef FILTER_H
#define FILTER_H

#include "packet_parser.h"

/**
 * 筛选配置
 */
typedef struct {
    int protocol;         // 协议筛选：0=不限制，其他值=只显示该协议
    char src_ip[16];      // 源 IP 筛选，空字符串=不限制
    char dst_ip[16];      // 目的 IP 筛选，空字符串=不限制
    uint16_t src_port;     // 源端口筛选：0=不限制
    uint16_t dst_port;     // 目的端口筛选：0=不限制
    uint16_t port;        // 通用端口筛选（任意一端匹配即可）：0=不限制
} FilterOptions;

/**
 * 初始化筛选配置为不限制
 * @param filter 筛选配置指针
 */
void init_filter(FilterOptions *filter);

/**
 * 检查数据包是否匹配筛选条件
 * @param info 数据包信息
 * @param filter 筛选配置
 * @return 匹配返回 1，不匹配返回 0
 */
int matches_filter(const PacketInfo *info, const FilterOptions *filter);

#endif