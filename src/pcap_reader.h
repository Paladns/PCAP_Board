#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "packet_parser.h"
#include "filter.h"

// 前向声明
struct PcapContextInternal;
typedef struct PcapContextInternal PcapContext;

/**
 * 创建 pcap 读取上下文
 * @param filename pcap 文件路径
 * @param filter 筛选配置
 * @return 上下文指针，失败返回 NULL
 */
PcapContext* pcap_create_context(const char *filename, FilterOptions *filter);

/**
 * 释放 pcap 读取上下文
 * @param ctx 上下文指针
 */
void pcap_free_context(PcapContext *ctx);

/**
 * 扫描 pcap 文件，建立索引
 * @param ctx 上下文指针
 * @return 成功返回匹配包数，失败返回 -1
 */
int pcap_scan_file(PcapContext *ctx);

/**
 * 获取匹配到的包数量
 * @param ctx 上下文指针
 * @return 匹配包数
 */
int pcap_get_count(PcapContext *ctx);

/**
 * 进入交互式查看模式
 * @param ctx 上下文指针
 * @param page_size 每页显示的包数
 * @return 成功返回 0，失败返回 -1
 */
int pcap_interactive_view(PcapContext *ctx, int page_size);

#endif