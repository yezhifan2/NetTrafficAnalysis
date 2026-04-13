#ifndef GRAPH_H
#define GRAPH_H

#include "common.h"

extern Graph* g; // 直接定义一个全局变量graph，毕竟整个程序就用这同一个graph

Graph* init_graph(int initial_capacity);

int find_node_index(const char* ip);

int add_node(const char* ip);

bool connect_vertex(PacketRecord* record);

void init_select();

void apply_filter(const char* any_ip, const char* src_ip, const char* dst_ip, int src_port, int dst_port, int tcp, int udp, int icmp, int other);

void free_graph();

#endif