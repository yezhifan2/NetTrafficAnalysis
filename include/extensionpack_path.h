#ifndef PATH_H
#define PATH_H

#include "common.h"

// 假设图最大节点数不超过 3000，如果超过可以适当调大
#define MAX_NODES 3000

int path[3][MAX_NODES];   // [0]当前路径，[1]最小跳数路径，[2]最小拥塞路径
int path_len[3];          // 记录三条路径的节点个数
double path_cong[3];      // 记录路径拥塞，[0]当前拥塞，[2]最小拥塞记录
bool visited[MAX_NODES];

void dfs(Graph *graph, int curr, int dst_idx);

void find_and_print_paths(Graph* graph, const char* src_ip, const char* dst_ip);

#endif