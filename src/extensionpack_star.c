#include "../include/common.h"
#include "../include/graph.h"
#include <stdbool.h>
bool included[3000] = {0};

int judge_star(Graph *g, int idx){
    for(int i=0;i<3000;i++){
        included[i]=0;
    }
    int single_degree = 0;
    EdgeNode *edge = g->nodes[idx].head_edge;
    while(edge){
        if(g->nodes[edge->dst_idx].degree == 1){
            included[edge->dst_idx]=1;
            single_degree++;
        }
        edge = edge->next_edge;
    }
    EdgeNode *inedge = g->nodes[idx].head_inedge;
    while(inedge){
        if(included[inedge->src_idx]==0&&g->nodes[inedge->src_idx].degree == 1){
            included[inedge->src_idx]=1;
            single_degree++;
        }
        inedge = inedge->next_edge;
    }
    return single_degree;
}

void print_star(Graph *g, int idx, int single_degree){
    printf("%s：", g->nodes[idx].ip_addr);
    int printed=0;
    for(int i=0;i<3000;i++){
        if(included[i]){
            printf("%s%s", g->nodes[i].ip_addr, (printed == single_degree-1)?",\n":"，");
            printed++;
        }
    }
    printf("星状节点 %s 拥有 %d 个边缘节点与之相连,\n", g->nodes[idx].ip_addr, printed);
}

// 主调函数：检测星型结构
void detect_star(Graph* g, int threshold){
    bool found_any = false;
    
    for(int i = 0; i < g->node_count; i++){
        if(g->nodes[i].degree >= threshold){
            int single_degree;
            if((single_degree = judge_star(g, i))>=threshold){
                found_any = true;
                print_star(g, i, single_degree);
            }
        }
    }
    // 如果遍历完全图，一个都没找到，给 Python 发送一个结束/未找到的提示
    if(!found_any){
        return;
    }
}

// 核心校验与打印函数
