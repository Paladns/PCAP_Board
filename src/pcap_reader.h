#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "packet_parser.h"
#include "filter.h"

// 前向声明
typedef struct PcapContext PcapContext;

// 创建上下文
PcapContext* pcap_create_context(const char *filename, FilterOptions *filter);

// 释放上下文
void pcap_free_context(PcapContext *ctx);

// 扫描文件并建立索引
int pcap_scan_file(PcapContext *ctx);

// 获取匹配的数据包数量
int pcap_get_count(PcapContext *ctx);

// 显示流量概览仪表盘
void pcap_show_stats(PcapContext *ctx);

// 等待按键
void pcap_wait_key();

// 读取指定范围的数据包并显示
int pcap_display_range(PcapContext *ctx, int start, int count);

// 交互式翻页查看
int pcap_interactive_view(PcapContext *ctx, int page_size);

// 标记/取消标记某个包
void pcap_toggle_mark(PcapContext *ctx, int index);

// 获取某个包的标记状态
int pcap_is_marked(PcapContext *ctx, int index);

#endif