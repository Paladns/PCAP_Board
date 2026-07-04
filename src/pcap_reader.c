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

// 打印表头
static void print_header() {
    printf("%-8s %-20s %-22s %-22s %-10s %-8s %s\n",
           "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info");
    printf("---------------------------------------------------------------------------------------------------------\n");
}

// 打印数据包信息
static void print_packet(const PacketInfo *info) {
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
           info->id, info->timestamp, source, dest,
           get_protocol_name(info->protocol), info->length, info_str);
}

// 创建上下文
PcapContext* pcap_create_context(const char *filename, FilterOptions *filter) {
    PcapContext *ctx = (PcapContext*)malloc(sizeof(PcapContext));
    if (!ctx) return NULL;
    
    ctx->filename = strdup(filename);
    ctx->index = (PacketIndex*)malloc(sizeof(PacketIndex) * INITIAL_CAPACITY);
    ctx->count = 0;
    ctx->capacity = INITIAL_CAPACITY;
    ctx->filter = filter;
    
    return ctx;
}

// 释放上下文
void pcap_free_context(PcapContext *ctx) {
    if (!ctx) return;
    free(ctx->filename);
    free(ctx->index);
    free(ctx);
}

// 扩展索引数组容量
static void expand_capacity(PcapContext *ctx) {
    int new_cap = ctx->capacity * 2;
    PacketIndex *new_idx = (PacketIndex*)realloc(ctx->index, sizeof(PacketIndex) * new_cap);
    if (new_idx) {
        ctx->index = new_idx;
        ctx->capacity = new_cap;
    }
}

// 扫描回调：只记录索引，不解析数据包
static void scan_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PcapContext *ctx = (PcapContext*)user_data;
    
    // 检查容量
    if (ctx->count >= ctx->capacity) {
        expand_capacity(ctx);
    }
    
    // 记录索引
    // 注意：这里我们无法直接获取文件偏移，所以需要特殊处理
    // 暂时我们记录时间戳和长度，用位置计数代替
    ctx->index[ctx->count].file_offset = ctx->count; // 用序号代替
    ctx->index[ctx->count].length = pkthdr->len;
    ctx->index[ctx->count].tv_sec = pkthdr->ts.tv_sec;
    ctx->index[ctx->count].tv_usec = pkthdr->ts.tv_usec;
    ctx->count++;
}

// 扫描文件并建立索引
int pcap_scan_file(PcapContext *ctx) {
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

// 显示范围回调：解析并显示
typedef struct {
    int target_start;
    int target_end;
    int current;
    PcapContext *ctx;
} DisplayState;

static void display_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    DisplayState *state = (DisplayState*)user_data;
    
    if (state->current >= state->target_start && state->current < state->target_end) {
        PacketInfo info;
        struct tm *timeinfo;
        char time_buf[64];
        
        // 解析数据包
        if (parse_packet(packet, pkthdr->len, &info) != 0) {
            state->current++;
            return;
        }
        
        info.id = state->current + 1;
        
        // 格式化时间戳
        time_t ts = pkthdr->ts.tv_sec;
        timeinfo = localtime(&ts);
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", timeinfo);
        snprintf(info.timestamp, sizeof(info.timestamp), "%s.%06ld", time_buf, (long)pkthdr->ts.tv_usec);
        
        // 应用筛选
        if (state->ctx->filter && !matches_filter(&info, state->ctx->filter)) {
            state->current++;
            return;
        }
        
        print_packet(&info);
    }
    
    state->current++;
}

// 读取指定范围的数据包并显示
int pcap_display_range(PcapContext *ctx, int start, int count) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    DisplayState state;
    
    handle = pcap_open_offline(ctx->filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "无法打开文件 %s: %s\n", ctx->filename, errbuf);
        return -1;
    }
    
    print_header();
    
    state.target_start = start;
    state.target_end = start + count;
    state.current = 0;
    state.ctx = ctx;
    
    if (pcap_loop(handle, 0, display_callback, (u_char*)&state) < 0) {
        fprintf(stderr, "读取数据包时出错: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    
    pcap_close(handle);
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
int pcap_interactive_view(PcapContext *ctx, int page_size) {
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
        if (start + count > ctx->count) {
            count = ctx->count - start;
        }
        
        printf("=== 第 %d/%d 页 (数据包 %d-%d/%d) ===\n", 
               current_page + 1, total_pages, start + 1, start + count, ctx->count);
        
        pcap_display_range(ctx, start, count);
        
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
