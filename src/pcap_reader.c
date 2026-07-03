#include "pcap_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>

typedef struct {
    char *filename;
    int count;
    FilterOptions *filter;
} PcapContextInternal;

// 处理每个捕获到的数据包
static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PcapContextInternal *ctx = (PcapContextInternal *)user;
    PacketInfo info;
    if (parse_packet(packet, pkthdr->len, &info) != 0) return;
    if (!matches_filter(&info, ctx->filter)) return;
    ctx->count++;
    char time_str[64];
    time_t ts_sec = pkthdr->ts.tv_sec;
    struct tm tm_t;
    localtime_s(&tm_t, &ts_sec);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", &tm_t);
    char flags_str[64];
    get_tcp_flags_str(info.tcp_flags, flags_str, sizeof(flags_str));
    printf("%5d  %-12s  %-15s:%-5d  ->  %-15s:%-5d  %-6s  %6d  %s\n",
           ctx->count, time_str,
           info.src_ip, info.src_port,
           info.dst_ip, info.dst_port,
           get_protocol_name(info.protocol),
           info.length, flags_str);
}

/*创建 pcap 读取上下文*/
PcapContext* pcap_create_context(const char *filename, FilterOptions *filter) {
    PcapContextInternal *ctx = (PcapContextInternal *)malloc(sizeof(PcapContextInternal));
    if (!ctx) return NULL;
    ctx->filename = _strdup(filename);
    ctx->filter = filter;
    ctx->count = 0;
    ctx->handle = NULL;
    return (PcapContext*)ctx;
}

/**
 * 释放 pcap 读取上下文
 * @param ctx 上下文指针
 */
void pcap_free_context(PcapContext *ctx_) {
    if (!ctx_) return;
    PcapContextInternal *ctx = (PcapContextInternal *)ctx_;
    if (ctx->handle) pcap_close(ctx->handle);
    free(ctx->filename);
    free(ctx);
}

/*扫描 pcap 文件，建立索引*/
int pcap_scan_file(PcapContext *ctx_) {
    PcapContextInternal *ctx = (PcapContextInternal *)ctx_;
    char errbuf[PCAP_ERRBUF_SIZE];
    ctx->handle = pcap_open_offline(ctx->filename, errbuf);
    if (!ctx->handle) {
        fprintf(stderr, "无法打开文件: %s\n", errbuf);
        return -1;
    }
    printf("%5s  %-12s  %-23s      %-23s  %-6s  %6s  %s\n",
           "No.", "Time", "Source", "Dest", "Proto", "Len", "Info");
    printf("---------------------------------------------------------------------------------------------------------\n");
    pcap_loop(ctx->handle, 0, packet_handler, (u_char*)ctx);
    pcap_close(ctx->handle);
    ctx->handle = NULL;
    printf("\n共显示 %d 个包\n", ctx->count);
    return ctx->count;
}

//获取匹配到的包数量
int pcap_get_count(PcapContext *ctx_) {
    return ((PcapContextInternal *)ctx_)->count;
}

//进入交互式查看模式
int pcap_interactive_view(PcapContext *ctx, int page_size) {
    return pcap_scan_file(ctx);
}