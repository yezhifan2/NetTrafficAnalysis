#include "../include/common.h"
#include "../include/graph.h"

// 并查集找祖先
int find_root(int parent[], int i) {
    if (parent[i] == i) return i;
    return parent[i] = find_root(parent, parent[i]); // 路径压缩
}

void visualize_subgraph(Graph* g, const char* target_ip) {
    int target_idx = find_node_index(target_ip);
    if (target_idx == -1) {
        printf("未找到目标 IP: %s\n", target_ip);
        return;
    }

    // 1. 初始化并查集
    int* parent = (int*)malloc(g->node_count * sizeof(int));
    for (int i = 0; i < g->node_count; i++) parent[i] = i;

    // 2. 遍历所有边进行 Union
    for (int i = 0; i < g->node_count; i++) {
        EdgeNode* edge = g->nodes[i].head_edge;
        while (edge) {
            int root_src = find_root(parent, edge->src_idx);
            int root_dst = find_root(parent, edge->dst_idx);
            if (root_src != root_dst) {
                parent[root_src] = root_dst; // 合并集合
            }
            edge = edge->next_edge;
        }
    }

    // 3. 找到 target_ip 的根节点
    int target_root = find_root(parent, target_idx);

    // 4. 再次遍历所有边，如果属于同一个连通分量，按规定格式打印发给 Python
    for (int i = 0; i < g->node_count; i++) {
        EdgeNode* edge = g->nodes[i].head_edge;
        while (edge) {
            if (find_root(parent, edge->src_idx) == target_root) {
                // Python端需要：[EDGE]src_ip,dst_ip,weight
                // 权重可以用 total_edge_bytes
                printf("[EDGE]%s,%s,%lld\n", 
                       g->nodes[edge->src_idx].ip_addr, 
                       g->nodes[edge->dst_idx].ip_addr, 
                       edge->total_edge_bytes);
            }
            edge = edge->next_edge;
        }
    }
    free(parent);
}