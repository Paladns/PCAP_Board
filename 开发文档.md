# PCAP 分析器 - 开发文档

## 项目简介
简单的命令行 PCAP 包解析工具。

## 技术选型
- 编程语言：C
- 依赖库：Npcap SDK
- 构建工具：Makefile

## 计划实现的功能
1. 读取并解析 pcap 文件
2. 支持解析：以太网、IP、TCP、UDP、ICMP
3. 输出包信息：No., Time, Source, Destination, Protocol, Length, Info
4. 支持按协议、IP、端口筛选
5. 交互式查看，支持翻页

## 目录结构规划
```
final/
├── src/
│   ├── main.c          # 入口
│   ├── pcap_reader.h/c # pcap 读取
│   ├── packet_parser.h/c # 包解析
│   └── filter.h/c     # 筛选
├── Makefile
└── README.md
```