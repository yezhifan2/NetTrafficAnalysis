#include <float.h>   // 为了使用 DBL_MAX
#include <limits.h>  // 为了使用 INT_MAX
#include "../include/common.h"
#include "../include/graph.h"
#include "../include/extensionpack_path.h"

// 全局状态数组
int path[3][MAX_NODES];   // [0]当前路径，[1]最小跳数路径，[2]最小拥塞路径
int path_len[3];          // 记录三条路径的节点个数
double path_cong[3];      // 记录路径拥塞，[0]当前拥塞，[2]最小拥塞记录
bool visited[MAX_NODES];  // O(1) 查环数组，替代 for 循环

// DFS 核心逻辑
void dfs(Graph *graph, int curr, int dst_idx) {
    path[0][path_len[0]] = curr; // 当前路径的最后一个节点，直接写入数组
    path_len[0]++; // 当前路径长度+1
    visited[curr] = true; // 标记数组将当前节点idx登记

    if(curr == dst_idx){ // 如果到了
        // 更新最小跳数路径
        if(path_len[0] < path_len[1]){
            path_cong[1] = path_cong[0];
            path_len[1] = path_len[0];
            for(int i = 0; i < path_len[0]; i++){
                path[1][i] = path[0][i];
            }
        }
        // 更新最小拥塞路径
        if(path_cong[0] < path_cong[2]){
            path_cong[2] = path_cong[0];
            path_len[2] = path_len[0];
            for(int i = 0; i < path_len[0]; i++){
                path[2][i] = path[0][i];
            }
        }
    } 
    else{
        // 3. 剪枝 (Pruning)
        // 只有当当前路径在跳数或拥塞上“还有希望”比最优解更好时，才继续往下搜
        if(path_len[0] < path_len[1] || path_cong[0] < path_cong[2]){
            EdgeNode *edge = graph->nodes[curr].head_edge;
            while(edge){
                // 如果遍历的下一个节点没有在当前路径中（未形成环）
                if(!visited[edge->dst_idx]){
                    // 计算这段边的拥塞度 = 流量 / 时间
                    double duration = edge->total_edge_duration > 0 ? edge->total_edge_duration : 0.001; 
                    double edge_cong = (double)edge->total_edge_bytes / duration;
                    // 累加拥塞度并向下递归
                    path_cong[0] += edge_cong;
                    dfs(graph, edge->dst_idx, dst_idx);
                    // 回溯：从下一层退回来时，把拥塞度减掉
                    path_cong[0] -= edge_cong;
                }
                edge = edge->next_edge;
            }
            EdgeNode *inedge = graph->nodes[curr].head_inedge;
            while(inedge){
                // 如果遍历的下一个节点没有在当前路径中（未形成环）
                if(!visited[inedge->src_idx]){
                    // 计算这段边的拥塞度 = 流量 / 时间
                    double duration = inedge->total_edge_duration > 0 ? inedge->total_edge_duration : 0.001; 
                    double inedge_cong = (double)inedge->total_edge_bytes / duration;
                    // 累加拥塞度并向下递归
                    path_cong[0] += inedge_cong;
                    dfs(graph, inedge->src_idx, dst_idx);
                    // 回溯：从下一层退回来时，把拥塞度减掉
                    path_cong[0] -= inedge_cong;
                }
                inedge = inedge->next_edge;
            }
        }
    }
    // 离开当前节点，取消访问标记，路径长度减1
    visited[curr] = false;
    path_len[0]--;
}

// 主调函数
void find_and_print_paths(Graph* graph, const char* src_ip, const char* dst_ip){
    int src_idx = find_node_index(src_ip);
    int dst_idx = find_node_index(dst_ip);
    
    if(src_idx == -1 || dst_idx == -1){
        printf("出错，找不到源 IP 或目的 IP。,\n");
        return;
    }

    // 初始化全局变量
    path_len[0] = 0;
    path_len[1] = INT_MAX;  // 最小跳数初始化为整型最大值
    path_len[2] = 0;

    path_cong[0] = 0.0;
    path_cong[1] = 0.0;
    path_cong[2] = DBL_MAX; // 最小拥塞初始化为浮点最大值

    for(int i = 0; i < graph->node_count; i++){
        visited[i] = false;
    }

    dfs(graph, src_idx, dst_idx); // 开始dfs，路径直接存在全局变量

    if(path_len[1] == INT_MAX){
        printf("未找到 %s 到 %s 的连通路径。,\n", src_ip, dst_ip);
        return;
    }
    printf("找到最小跳数路径：,\n");
    for(int i = 0; i < path_len[1]; i++){
        printf("%s%s", graph->nodes[path[1][i]].ip_addr, (i == path_len[1]-1) ? ",\n" : " -> ");
    }
    printf("总跳数: %d,\n", path_len[1] - 1);
    printf("总拥塞度: %.3lf,\n", path_cong[1]);

    printf("找到最小拥塞路径：,\n");
    for (int i = 0; i < path_len[2]; i++) {
        printf("%s%s", graph->nodes[path[2][i]].ip_addr, (i == path_len[2]-1) ? ",\n" : " -> ");
    }
    printf("总跳数: %d,\n", path_len[2] - 1);
    printf("总拥塞度: %.3lf,\n", path_cong[2]);
}