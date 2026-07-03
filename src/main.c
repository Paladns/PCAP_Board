#include <stdio.h>
#include "pcap_reader.h"
#include "filter.h"

// 主程序入口
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("使用方法: %s <pcap文件>\n", argv[0]);
        return 1;
    }
    FilterOptions filter;
    init_filter(&filter);
    PcapContext *ctx = pcap_create_context(argv[1], &filter);
    if (!ctx) {
        fprintf(stderr, "创建上下文失败\n");
        return 1;
    }
    pcap_scan_file(ctx);
    pcap_free_context(ctx);
    return 0;
}