#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "pcap_reader.h"
#include "filter.h"

// 读取一行输入（去除换行符）
static void read_line(char *buf, int size) {
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    
    // 去掉换行符
    int len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') {
        buf[len-1] = '\0';
    }
    if (len > 1 && buf[len-2] == '\r') {
        buf[len-2] = '\0';
    }
}

// 交互式配置筛选条件
static void configure_filter_interactive(FilterOptions *filter) {
    char buf[256];
    
    printf("\n============= 配置筛选条件 =============\n");
    printf("直接回车表示不设置该条件\n\n");
    
    // 协议
    printf("协议筛选 (tcp/udp/icmp, 回车跳过): ");
    read_line(buf, sizeof(buf));
    if (strcmp(buf, "tcp") == 0 || strcmp(buf, "TCP") == 0) {
        filter->protocol = 6;
    } else if (strcmp(buf, "udp") == 0 || strcmp(buf, "UDP") == 0) {
        filter->protocol = 17;
    } else if (strcmp(buf, "icmp") == 0 || strcmp(buf, "ICMP") == 0) {
        filter->protocol = 1;
    }
    
    // 源 IP
    printf("源 IP (例如 192.168.*, 回车跳过): ");
    read_line(buf, sizeof(buf));
    if (buf[0] != '\0') {
        strncpy(filter->src_ip, buf, sizeof(filter->src_ip) - 1);
    }
    
    // 目的 IP
    printf("目的 IP (例如 192.168.*, 回车跳过): ");
    read_line(buf, sizeof(buf));
    if (buf[0] != '\0') {
        strncpy(filter->dst_ip, buf, sizeof(filter->dst_ip) - 1);
    }
    
    // 源端口
    printf("源端口 (例如 1234, 回车跳过): ");
    read_line(buf, sizeof(buf));
    if (buf[0] != '\0') {
        filter->src_port = atoi(buf);
    }
    
    // 目的端口
    printf("目的端口 (例如 80, 回车跳过): ");
    read_line(buf, sizeof(buf));
    if (buf[0] != '\0') {
        filter->dst_port = atoi(buf);
    }
    
    // 任意方向端口
    printf("任意方向端口 (例如 443, 回车跳过): ");
    read_line(buf, sizeof(buf));
    if (buf[0] != '\0') {
        filter->port = atoi(buf);
    }
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    char filename[512];
    FilterOptions filter;
    int page_size = 20;
    char buf[256];
    
    // 初始化筛选选项
    init_filter(&filter);
    
    printf("========================================\n");
    printf("    Pcap 数据包分析工具\n");
    printf("========================================\n\n");
    
    // 获取文件名
    printf("请输入 pcap 文件名: ");
    read_line(filename, sizeof(filename));
    if (filename[0] == '\0') {
        printf("错误: 未提供文件名\n");
        return 1;
    }
    
    // 询问是否配置筛选
    printf("\n是否配置筛选条件？(y/n, 默认 n): ");
    read_line(buf, sizeof(buf));
    if (strcmp(buf, "y") == 0 || strcmp(buf, "Y") == 0) {
        configure_filter_interactive(&filter);
    }
    
    // 创建上下文并扫描文件
    printf("\n正在扫描文件: %s...\n", filename);
    PcapContext *ctx = pcap_create_context(filename, &filter);
    if (!ctx) {
        printf("错误: 内存不足\n");
        return 1;
    }
    
    if (pcap_scan_file(ctx) != 0) {
        pcap_free_context(ctx);
        return 1;
    }
    
    printf("扫描完成，共 %d 个数据包\n\n", pcap_get_count(ctx));
    
    if (pcap_get_count(ctx) == 0) {
        printf("没有找到数据包\n");
        pcap_free_context(ctx);
        return 0;
    }
    
    // 显示流量概览
    pcap_show_stats(ctx);
    pcap_wait_key();
    
    // 交互式查看
    pcap_interactive_view(ctx, page_size);
    
    // 清理
    pcap_free_context(ctx);
    return 0;
}