#include "pcap_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#ifdef _WIN32
#include <pcap.h>
#include <conio.h>
#else
#include <pcap/pcap.h>
#include <termios.h>
#include <unistd.h>
#endif

#define INITIAL_CAPACITY 1000

// 统计结构
typedef struct {
    uint64_t total_bytes;
    int tcp_count;
    int udp_count;
    int icmp_count;
    int other_count;
    long first_sec;
    long first_usec;
    long last_sec;
    long last_usec;
    // 端口统计（简单计数）
    int port_80;
    int port_443;
    int port_53;
    int port_22;
} TrafficStats;

// 我们直接存储匹配的完整数据包信息（带原包号）
typedef struct {
    PacketInfo info;
    int original_id;
} CachedPacket;

// 修改上下文：存储缓存的数据包而不是索引
typedef struct {
    char *filename;
    CachedPacket *packets;   // 缓存的数据包数组
    int count;               // 匹配的数据包数
    int capacity;            // 数组容量
    FilterOptions *filter;
    TrafficStats stats;      // 流量统计
} PcapContextInternal;

// 初始化统计
static void init_stats(TrafficStats *stats) {
    memset(stats, 0, sizeof(TrafficStats));
    stats->first_sec = -1;
}

// 更新统计
static void update_stats(TrafficStats *stats, const PacketInfo *info, long sec, long usec) {
    stats->total_bytes += info->length;
    
    if (info->protocol == 6) stats->tcp_count++;
    else if (info->protocol == 17) stats->udp_count++;
    else if (info->protocol == 1) stats->icmp_count++;
    else stats->other_count++;
    
    // 记录时间跨度
    if (stats->first_sec == -1 || sec < stats->first_sec) {
        stats->first_sec = sec;
        stats->first_usec = usec;
    }
    if (sec > stats->last_sec || (sec == stats->last_sec && usec > stats->last_usec)) {
        stats->last_sec = sec;
        stats->last_usec = usec;
    }
    
    // 简单的常用端口统计
    if (info->src_port == 80 || info->dst_port == 80) stats->port_80++;
    if (info->src_port == 443 || info->dst_port == 443) stats->port_443++;
    if (info->src_port == 53 || info->dst_port == 53) stats->port_53++;
    if (info->src_port == 22 || info->dst_port == 22) stats->port_22++;
}

// 打印表头
static void print_header() {
    printf("%-8s %-20s %-22s %-22s %-10s %-8s %s\n",
           "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info");
    printf("---------------------------------------------------------------------------------------------------------\n");
}

// 打印数据包信息
static void print_packet(const PacketInfo *info, int original_id) {
    char source[64];
    char dest[64];
    char info_str[128];
    char flags_str[64];
    
    // 格式化源地址
    if (info->src_port != 0) {
        snprintf(source, sizeof(source), "%s:%d", info->src_ip, info->src_port);
    } else {
        snprintf(source, sizeof(source), "%s", info->src_ip);
    }
    
    // 格式化目的地址
    if (info->dst_port != 0) {
        snprintf(dest, sizeof(dest), "%s:%d", info->dst_ip, info->dst_port);
    } else {
        snprintf(dest, sizeof(dest), "%s", info->dst_ip);
    }
    
    // 格式化 Info 字段
    if (info->protocol == 6) { // TCP
        get_tcp_flags_str(info->tcp_flags, flags_str, sizeof(flags_str));
        snprintf(info_str, sizeof(info_str), "[%s]", flags_str);
    } else {
        info_str[0] = '-';
        info_str[1] = '\0';
    }
    
    printf("%-8d %-20s %-22s %-22s %-10s %-8u %s\n",
           original_id, info->timestamp, source, dest,
           get_protocol_name(info->protocol), info->length, info_str);
}

// 创建上下文
PcapContext* pcap_create_context(const char *filename, FilterOptions *filter) {
    PcapContextInternal *ctx = (PcapContextInternal*)malloc(sizeof(PcapContextInternal));
    if (!ctx) return NULL;
    
    ctx->filename = strdup(filename);
    ctx->packets = (CachedPacket*)malloc(sizeof(CachedPacket) * INITIAL_CAPACITY);
    ctx->count = 0;
    ctx->capacity = INITIAL_CAPACITY;
    ctx->filter = filter;
    init_stats(&ctx->stats);
    
    return (PcapContext*)ctx;
}

// 释放上下文
void pcap_free_context(PcapContext *ctx_) {
    PcapContextInternal *ctx = (PcapContextInternal*)ctx_;
    if (!ctx) return;
    free(ctx->filename);
    free(ctx->packets);
    free(ctx);
}

// 扩展缓存数组容量
static void expand_capacity(PcapContextInternal *ctx) {
    int new_cap = ctx->capacity * 2;
    CachedPacket *new_packets = (CachedPacket*)realloc(ctx->packets, sizeof(CachedPacket) * new_cap);
    if (new_packets) {
        ctx->packets = new_packets;
        ctx->capacity = new_cap;
    }
}

// 扫描回调：解析并筛选，保存匹配的包
static void scan_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PcapContextInternal *ctx = (PcapContextInternal*)user_data;
    static int packet_counter = 1;  // 原包号计数器
    
    PacketInfo info;
    struct tm *timeinfo;
    char time_buf[64];
    
    // 解析数据包
    if (parse_packet(packet, pkthdr->len, &info) != 0) {
        packet_counter++;
        return;
    }
    
    // 格式化时间戳
    time_t ts = pkthdr->ts.tv_sec;
    timeinfo = localtime(&ts);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", timeinfo);
    snprintf(info.timestamp, sizeof(info.timestamp), "%s.%06ld", time_buf, (long)pkthdr->ts.tv_usec);
    
    // 应用筛选
    if (ctx->filter && !matches_filter(&info, ctx->filter)) {
        packet_counter++;
        return;
    }
    
    // 更新统计
    update_stats(&ctx->stats, &info, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
    
    // 检查容量
    if (ctx->count >= ctx->capacity) {
        expand_capacity(ctx);
    }
    
    // 保存
    ctx->packets[ctx->count].info = info;
    ctx->packets[ctx->count].original_id = packet_counter;
    ctx->count++;
    
    packet_counter++;
}

// 扫描文件并建立索引
int pcap_scan_file(PcapContext *ctx_) {
    PcapContextInternal *ctx = (PcapContextInternal*)ctx_;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    handle = pcap_open_offline(ctx->filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "无法打开文件 %s: %s\n", ctx->filename, errbuf);
        return -1;
    }
    
    if (pcap_loop(handle, 0, scan_callback, (u_char*)ctx) < 0) {
        fprintf(stderr, "扫描文件时出错: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    
    pcap_close(handle);
    return 0;
}

// 获取匹配的数据包数量
int pcap_get_count(PcapContext *ctx_) {
    PcapContextInternal *ctx = (PcapContextInternal*)ctx_;
    return ctx ? ctx->count : 0;
}

// 格式化时间跨度
static void format_duration(long first_sec, long first_usec, long last_sec, long last_usec, char *buf, int buf_size) {
    if (first_sec == -1) {
        strncpy(buf, "N/A", buf_size);
        return;
    }
    
    long total_usec = (last_sec - first_sec) * 1000000LL + (last_usec - first_usec);
    long total_sec = total_usec / 1000000;
    
    int hours = total_sec / 3600;
    int mins = (total_sec % 3600) / 60;
    int secs = total_sec % 60;
    
    if (hours > 0) {
        snprintf(buf, buf_size, "%dh %dm %ds", hours, mins, secs);
    } else if (mins > 0) {
        snprintf(buf, buf_size, "%dm %ds", mins, secs);
    } else {
        snprintf(buf, buf_size, "%d.%03lds", secs, (int)((total_usec % 1000000) / 1000));
    }
}

// 格式化字节数
static void format_bytes(uint64_t bytes, char *buf, int buf_size) {
    if (bytes >= 1024 * 1024 * 1024) {
        snprintf(buf, buf_size, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024 * 1024) {
        snprintf(buf, buf_size, "%.2f MB", bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        snprintf(buf, buf_size, "%.2f KB", bytes / 1024.0);
    } else {
        snprintf(buf, buf_size, "%llu B", (unsigned long long)bytes);
    }
}

// 显示流量概览仪表盘
void pcap_show_stats(PcapContext *ctx_) {
    PcapContextInternal *ctx = (PcapContextInternal*)ctx_;
    TrafficStats *stats = &ctx->stats;
    char dur_buf[64];
    char bytes_buf[64];
    
    format_duration(stats->first_sec, stats->first_usec, stats->last_sec, stats->last_usec, dur_buf, sizeof(dur_buf));
    format_bytes(stats->total_bytes, bytes_buf, sizeof(bytes_buf));
    
    printf("\n");
    printf("========================================\n");
    printf("          流量概览仪表盘\n");
    printf("========================================\n\n");
    
    printf("  总计:\n");
    printf("    数据包数: %d\n", ctx->count);
    printf("    字节数:   %s\n", bytes_buf);
    printf("    时间跨度: %s\n\n", dur_buf);
    
    printf("  协议分布:\n");
    printf("    TCP:   %d\n", stats->tcp_count);
    printf("    UDP:   %d\n", stats->udp_count);
    printf("    ICMP:  %d\n", stats->icmp_count);
    printf("    其他:  %d\n\n", stats->other_count);
    
    printf("  常用端口:\n");
    printf("    80 (HTTP):  %d\n", stats->port_80);
    printf("    443 (HTTPS):%d\n", stats->port_443);
    printf("    53 (DNS):   %d\n", stats->port_53);
    printf("    22 (SSH):   %d\n\n", stats->port_22);
    
    printf("========================================\n");
}

// 等待按键
void pcap_wait_key() {
    printf("\n按任意键查看数据包列表...\n");
#ifdef _WIN32
    _getch();
#else
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
}

// 读取指定范围的数据包并显示
int pcap_display_range(PcapContext *ctx_, int start, int count) {
    PcapContextInternal *ctx = (PcapContextInternal*)ctx_;
    int end = start + count;
    if (end > ctx->count) {
        end = ctx->count;
    }
    
    print_header();
    for (int i = start; i < end; i++) {
        print_packet(&ctx->packets[i].info, ctx->packets[i].original_id);
    }
    
    return 0;
}

#ifdef _WIN32
static int get_key() {
    return _getch();
}
#else
static int get_key() {
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}
#endif

// 交互式翻页查看
int pcap_interactive_view(PcapContext *ctx_, int page_size) {
    PcapContextInternal *ctx = (PcapContextInternal*)ctx_;
    int current_page = 0;
    int total_pages = (ctx->count + page_size - 1) / page_size;
    int key;
    char input[32];
    int input_idx = 0;
    
    while (1) {
        // 清屏（简单的输出换行）
        printf("\n\n");
        
        int start = current_page * page_size;
        int count = page_size;
        int end = start + count;
        if (end > ctx->count) {
            end = ctx->count;
            count = end - start;
        }
        
        printf("=== 第 %d/%d 页 (数据包 %d-%d/%d) ===\n", 
               current_page + 1, total_pages, start + 1, end, ctx->count);
        
        pcap_display_range((PcapContext*)ctx, start, count);
        
        printf("\n操作: n=下一页, p=上一页, [数字]=跳转到页, q=退出\n> ");
        
        input_idx = 0;
        while (1) {
            key = get_key();
            
            if (key == 'q' || key == 'Q') {
                return 0;
            } else if (key == 'n' || key == 'N' || key == ' ') {
                if (current_page < total_pages - 1) {
                    current_page++;
                }
                break;
            } else if (key == 'p' || key == 'P') {
                if (current_page > 0) {
                    current_page--;
                }
                break;
            } else if (key == '\r' || key == '\n') {
                if (input_idx > 0) {
                    input[input_idx] = '\0';
                    int page = atoi(input) - 1;
                    if (page >= 0 && page < total_pages) {
                        current_page = page;
                    }
                }
                break;
            } else if (key >= '0' && key <= '9' && input_idx < 30) {
                input[input_idx++] = key;
                printf("%c", key);
            }
        }
    }
}