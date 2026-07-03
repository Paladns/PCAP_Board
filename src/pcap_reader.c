#include "pcap_reader.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *filename;
    int count;
    FilterOptions *filter;
} PcapContextInternal;

/*创建 pcap 读取上下文*/
PcapContext* pcap_create_context(const char *filename, FilterOptions *filter) {
    return NULL;
}

/**
 * 释放 pcap 读取上下文
 * @param ctx 上下文指针
 */
void pcap_free_context(PcapContext *ctx_) {
}

/*扫描 pcap 文件，建立索引*/
int pcap_scan_file(PcapContext *ctx_) {
    return 0;
}

//获取匹配到的包数量
int pcap_get_count(PcapContext *ctx_) {
    return 0;
}

//进入交互式查看模式
int pcap_interactive_view(PcapContext *ctx_, int page_size) {
    return 0;
}