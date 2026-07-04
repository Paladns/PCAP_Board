#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "pcap_reader.h"
#include "filter.h"

// 显示帮助信息
void print_help(const char *prog_name) {
    printf("用法: %s -f <pcap文件> [选项]\n\n", prog_name);
    printf("选项:\n");
    printf("  -f <文件>     指定 pcap 文件（必需）\n");
    printf("  -tcp          只显示 TCP 数据包\n");
    printf("  -udp          只显示 UDP 数据包\n");
    printf("  -icmp         只显示 ICMP 数据包\n");
    printf("  -src <IP>     筛选源 IP 地址\n");
    printf("  -dst <IP>     筛选目的 IP 地址\n");
    printf("  -sport <port> 筛选源端口\n");
    printf("  -dport <port> 筛选目的端口\n");
    printf("  -port <port>  筛选任意方向的端口\n");
    printf("  -size <num>   每页显示数量（默认 20）\n");
    printf("  -h            显示帮助信息\n");
    printf("\n交互式操作:\n");
    printf("  n / 空格      下一页\n");
    printf("  p             上一页\n");
    printf("  [数字]        跳转到指定页\n");
    printf("  q             退出\n");
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    const char *filename = NULL;
    FilterOptions filter = {0};
    int page_size = 20;
    int i;

    // 初始化筛选选项
    init_filter(&filter);

    // 解析命令行参数
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            filename = argv[++i];
        } else if (strcmp(argv[i], "-tcp") == 0) {
            filter.protocol = 6;
        } else if (strcmp(argv[i], "-udp") == 0) {
            filter.protocol = 17;
        } else if (strcmp(argv[i], "-icmp") == 0) {
            filter.protocol = 1;
        } else if (strcmp(argv[i], "-src") == 0 && i + 1 < argc) {
            strncpy(filter.src_ip, argv[++i], sizeof(filter.src_ip) - 1);
        } else if (strcmp(argv[i], "-dst") == 0 && i + 1 < argc) {
            strncpy(filter.dst_ip, argv[++i], sizeof(filter.dst_ip) - 1);
        } else if (strcmp(argv[i], "-sport") == 0 && i + 1 < argc) {
            filter.src_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-dport") == 0 && i + 1 < argc) {
            filter.dst_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
            filter.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-size") == 0 && i + 1 < argc) {
            page_size = atoi(argv[++i]);
            if (page_size < 1) page_size = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        } else {
            printf("未知选项: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    // 检查是否指定了文件
    if (filename == NULL) {
        printf("错误: 请使用 -f 选项指定 pcap 文件\n");
        print_help(argv[0]);
        return 1;
    }

    // 创建上下文并扫描文件
    printf("正在扫描文件: %s...\n", filename);
    PcapContext *ctx = pcap_create_context(filename, &filter);
    if (!ctx) {
        printf("错误: 内存不足\n");
        return 1;
    }

    if (pcap_scan_file(ctx) != 0) {
        pcap_free_context(ctx);
        return 1;
    }

    printf("扫描完成，共 %d 个数据包\n\n", ctx->count);

    if (ctx->count == 0) {
        printf("没有找到数据包\n");
        pcap_free_context(ctx);
        return 0;
    }

    // 交互式查看
    pcap_interactive_view(ctx, page_size);

    // 清理
    pcap_free_context(ctx);

    return 0;
}