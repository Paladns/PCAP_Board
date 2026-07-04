#include "filter.h"
#include <string.h>

// 初始化筛选条件
void init_filter(FilterOptions *filter) {
    filter->protocol = -1;
    filter->src_ip[0] = '\0';
    filter->dst_ip[0] = '\0';
    filter->src_port = -1;
    filter->dst_port = -1;
    filter->port = -1;
}

// 检查数据包是否匹配筛选条件
int matches_filter(const PacketInfo *packet, const FilterOptions *filter) {
    // 协议筛选
    if (filter->protocol != -1 && packet->protocol != filter->protocol) {
        return 0;
    }
    
    // 源 IP 筛选
    if (filter->src_ip[0] != '\0' && strcmp(packet->src_ip, filter->src_ip) != 0) {
        return 0;
    }
    
    // 目的 IP 筛选
    if (filter->dst_ip[0] != '\0' && strcmp(packet->dst_ip, filter->dst_ip) != 0) {
        return 0;
    }
    
    // 源端口筛选
    if (filter->src_port != -1 && packet->src_port != filter->src_port) {
        return 0;
    }
    
    // 目的端口筛选
    if (filter->dst_port != -1 && packet->dst_port != filter->dst_port) {
        return 0;
    }
    
    // 任意方向端口筛选
    if (filter->port != -1 && packet->src_port != filter->port && packet->dst_port != filter->port) {
        return 0;
    }
    
    return 1;
}