#include "../include/common.h"
#include "../include/graph.h"
// 辅助函数：将字符串 IP 转为整数比较大小
unsigned int ip_to_int(const char* ip) {
    unsigned int b1, b2, b3, b4;
    sscanf(ip, "%u.%u.%u.%u", &b1, &b2, &b3, &b4);
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}

void check_security_rule(Graph* g, const char* ip1, const char* ip2, const char* ip3, int action) {
    unsigned int target = ip_to_int(ip1);
    unsigned int range_start = ip_to_int(ip2);
    unsigned int range_end = ip_to_int(ip3);
    if (range_start > range_end) { unsigned int tmp = range_start; range_start = range_end; range_end = tmp; }

    bool found = false;
    // printf("违规会话列表:,\n");

    for (int i = 0; i < g->node_count; i++) {
        EdgeNode* edge = g->nodes[i].head_edge;
        while (edge) { // 遍历所有节点
            unsigned int src_val = ip_to_int(g->nodes[edge->src_idx].ip_addr);
            unsigned int dst_val = ip_to_int(g->nodes[edge->dst_idx].ip_addr);
            
            // 判断是否是 ip1 与 范围内IP 的通信
            enum whether_in_list{
                INSIDE,
                OUTSIDE,
                NONE
            } ;
            enum whether_in_list is_violation = NONE;
            if(src_val == target){
                if(dst_val >= range_start && dst_val <= range_end){
                    is_violation = INSIDE;
                }
                else{
                    is_violation = OUTSIDE;
                }
            }
            else if(dst_val == target){
                if(src_val >= range_start && src_val <= range_end){
                    is_violation = INSIDE;
                }
                else{
                    is_violation = OUTSIDE;
                }
            }

            // action == 0 表示禁止，如果有通信就是违规
            // action == 1 表示允许，如果有通信就不是违规
            if (is_violation == INSIDE && action == 0) {
                printf("%s -> %s (流量: %lld Bytes),\n", 
                       g->nodes[edge->src_idx].ip_addr, 
                       g->nodes[edge->dst_idx].ip_addr, 
                       edge->total_edge_bytes);
                found = true;
            }
            else if (is_violation == OUTSIDE && action == 1) {
                printf("%s -> %s (流量: %lld Bytes),\n", 
                       g->nodes[edge->src_idx].ip_addr, 
                       g->nodes[edge->dst_idx].ip_addr, 
                       edge->total_edge_bytes);
                found = true;
            }
            edge = edge->next_edge;
        }
    }
    if (!found) printf("未发现违规通信。,\n");
}