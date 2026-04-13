/*
学到了enum类型的使用；遗留问题：enum取值和数字的默认对应关系是怎么回事
掌握了typrdef，ifndef
听闻了realloc，sscanf
学会了extern和static
*/
#ifndef COMMON_H
#define COMMON_H

#define __USE_MINGW_ANSI_STDIO 1
#define SEND_ERROR() printf("Error\n");
#define SEND_END() printf("[Waiting...]\n");
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <float.h> // 需要用到 DBL_MAX

// 最大字符串长度
#define MAX_IP_LEN 16
#define MAX_LINE_LEN 1024

// 协议类型映射 (PDF 2.3)
typedef enum {              // enum？enumeration枚举，enum是一个类型！！括号中的是它的取值
    PROTO_ICMP = 1,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_UNKNOWN = 0
} ProtocolType;

// 原始csv数据记录
typedef struct PacketRecord{
    char src_ip[MAX_IP_LEN];    // source ip
    char dst_ip[MAX_IP_LEN];    // destination ip
    int protocol;
    int src_port;
    int dst_port;
    long long data_size;
    double duration;
    bool is_selected; // >>> 新增：记录这条记录当前是否符合筛选条件
    // 为配合edge索引，还是添加一个指针
    struct PacketRecord* next_record;
} PacketRecord;

// 图的边 (Edge)：表示从一个 IP 到另一个 IP 的连接
// 采用邻接表结构，PDF 2.2 建议合并会话
typedef struct EdgeNode{
    int src_idx;
    int dst_idx;              // 目标节点在节点数组中的下标

    long long total_edge_bytes;      
    double total_edge_duration;      // 总持续时间
    int total_record; // 统计一共有多少条record
    
    // 按被选择的指标统计 (用于扩展分析)
    long long select_edge_bytes;
    double select_edge_duration;
    int select_record; // 筛选后该会话剩下的记录数
    
    PacketRecord* head_record; // 链表里面的小链表
    PacketRecord* tail_record; // 存一下尾指针比较方便

    struct EdgeNode* next_edge;      // 指向下一条边的指针
} EdgeNode;

// 图的节点 (Vertex)：表示一个 IP
typedef struct {
    char ip_addr[MAX_IP_LEN];   // IP 地址字符串
    EdgeNode* head_edge;             // 邻接表头指针 (指向该 IP 发出的第一条边)
    EdgeNode* head_inedge;
    
    // 统计数据 (用于排序和筛选)
    long long total_send_bytes; // 发送总流量
    long long total_recv_bytes; // 接收总流量 (需要在构建图时反向更新，或者遍历计算)
    double send_ratio;
    int degree;                 // 度 (连接数量，用于星型结构检测)

    long long select_send_bytes; // 被选择的发送总流量（可以设计一个选择系统，不仅限于http）
    long long select_recv_bytes; // 被选择的接受总流量
    double select_send_ratio;
    int select_degree;

} VertexNode;

// 图的主结构
typedef struct {
    VertexNode* nodes;          // 节点数组 (动态分配)
    int node_count;             // 当前节点数
    int edge_count;
    int capacity;               // 数组容量
} Graph;

// 排序模式汇总
typedef enum {
    Vertex,
    Edge,
    Record
} ModeType;

// 节点排序筛选模式
typedef enum {
    TotalBytes,
    SendBytes,
    Recvbytes,
    Ipaddr,
    Degree
} VertexSortType;

// 边排序筛选模式
typedef enum {
    EdgeSrcIP,
    EdgeDstIP,
    EdgeBytes,
    EdgeRecord,
} EdgeSortType;

// 记录排序筛选模式
typedef enum {
    SrcIP,
    DstIP,
    SrcPort,
    DstPort,
    RecordBytes,
    RecordDuration,
} RecordSortType;

#endif