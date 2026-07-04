# PCAP 分析器

简单的命令行 PCAP 包解析工具（开发中）

## 迭代记录

- **阶段一**：基础解析与打印（原始包逐个解析并打印）
- **阶段二**：交互式翻页浏览（先扫描建立索引，再支持 n/p/q 翻页查看）

## 目录结构说明

```
original/
├── 开发文档.md          # 项目规划
├── Makefile             # 构建脚本
├── README.md            # 你在看的文件
└── src/
    ├── main.c           # 程序入口，处理参数
    ├── packet_parser.h  # 数据包解析模块（头文件）
    ├── packet_parser.c  # 数据包解析模块（实现）
    ├── filter.h         # 筛选模块（头文件）
    ├── filter.c         # 筛选模块（实现）
    ├── pcap_reader.h    # pcap 文件读取（头文件）
    └── pcap_reader.c    # pcap 文件读取（实现）
```

## 模块作用与协作流程

整体流程：
```
main.c 
  ↓ 调用
pcap_reader.c  ← 第一遍扫描建立索引
  ↓ 第二遍进入交互模式（n/p/q 翻页）
packet_parser.c  ← 把二进制包解析成 PacketInfo
  ↓ 判断是否显示时调用
filter.c  ← 检查是否匹配筛选条件
```

### 各个文件的具体作用

| 文件 | 作用 |
|------|------|
| **main.c** | 入口：解析命令行参数（比如 pcap 文件名），初始化筛选配置，调用 pcap_reader 先扫描后进入交互查看 |
| **packet_parser.h/c** | 解析器：负责把原始以太网/IP/TCP/UDP/ICMP 二进制数据解析成人能看懂的信息（源IP、目的IP、端口、协议等） |
| **filter.h/c** | 筛选器：拿着解析好的 PacketInfo，判断这个包是否符合用户想要看的条件（比如只看 TCP、只看某个 IP），符合就返回 1，不符合就返回 0 |
| **pcap_reader.h/c** | 读取器：负责打开 pcap 文件，先扫描一遍建立索引，然后按页读取并显示，支持 n/p/q 交互，里面会调用 packet_parser 解析包，调用 filter 判断要不要显示 |
| **Makefile** | 一键编译脚本 |

## 使用说明

```bash
# 编译
make

# 运行
./build/pcap-parser.exe ../traffic.pcap

# 交互按键
# n: 下一页
# p: 上一页
# q: 退出