#include "filter.h"
#include <string.h>

// 为了支持通配符匹配，定义一个简单的 IP 匹配函数
static int ip_match(const char *ip, const char *pattern) {
    if (pattern[0] == '\0') return 1;
    char buf[16];
    strncpy(buf, pattern, 15);
    buf[15] = '\0';
    char *star = strchr(buf, '*');
    if (star) {
        *star = '\0';
        return strncmp(ip, buf, strlen(buf)) == 0;
    }
    return strcmp(ip, pattern) == 0;
}


//初始化筛选配置为不限制
void init_filter(FilterOptions *filter) {
    memset(filter, 0, sizeof(FilterOptions));
    filter->protocol = 0;
    filter->src_port = 0;
    filter->dst_port = 0;
    filter->port = 0;
    filter->src_ip[0] = '\0';
    filter->dst_ip[0] = '\0';
}

/**
 * 检查数据包是否匹配筛选条件
 * @param info 数据包信息
 * @param filter 筛选配置
 * @return 匹配返回 1，不匹配返回 0
 */
int matches_filter(const PacketInfo *info, const FilterOptions *filter) {
    if (filter->protocol != 0 && info->protocol != filter->protocol) {
        return 0;
    }
    if (filter->src_ip[0] != '\0' && !ip_match(info->src_ip, filter->src_ip)) {
        return 0;
    }
    if (filter->dst_ip[0] != '\0' && !ip_match(info->dst_ip, filter->dst_ip)) {
        return 0;
    }
    if (filter->src_port != 0 && info->src_port != filter->src_port) {
        return 0;
    }
    if (filter->dst_port != 0 && info->dst_port != filter->dst_port) {
        return 0;
    }
    if (filter->port != 0 && info->src_port != filter->port && info->dst_port != filter->port) {
        return 0;
    }
    return 1;
}