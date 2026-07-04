#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "packet_parser.h"
#include "filter.h"

// 数据包索引结构：记录在文件中的位置
typedef struct {
    long file_offset;   // 在文件中的偏移
    uint32_t length;    // 数据包长度
    long tv_sec;        // 时间戳 - 秒
    long tv_usec;       // 时间戳 - 微秒
} PacketIndex;

// 上下文结构
typedef struct {
    char *filename;
    PacketIndex *index;  // 数据包索引数组
    int count;           // 总数据包数
    int capacity;        // 数组容量
    FilterOptions *filter;
} PcapContext;

// 创建上下文
PcapContext* pcap_create_context(const char *filename, FilterOptions *filter);

// 释放上下文
void pcap_free_context(PcapContext *ctx);

// 扫描文件并建立索引
int pcap_scan_file(PcapContext *ctx);

// 读取指定范围的数据包并显示
int pcap_display_range(PcapContext *ctx, int start, int count);

// 交互式翻页查看
int pcap_interactive_view(PcapContext *ctx, int page_size);

#endif