#include "../include/common.h"
#include "../include/graph.h"

Graph* g;

// 初始化图，以后要是不够的话，需要再扩充
Graph* init_graph(int initial_capacity){
    Graph* g=(Graph*)malloc(sizeof(Graph));
    g->nodes=(VertexNode*)malloc(sizeof(VertexNode)*initial_capacity);
    g->node_count=0;
    g->edge_count=0; 
    g->capacity=initial_capacity;
    return g;
}

// 查找 IP 在节点数组中的下标，找不到返回 -1
int find_node_index(const char* ip){
    for(int i=0; i<g->node_count; i++) {
        if(strcmp(g->nodes[i].ip_addr, ip)==0) {
            return i;
        }
    }
    return -1;
}

// 添加节点 (如果不存在则添加，存在则返回下标)
int add_node(const char* ip) {
    int idx = find_node_index(ip);
    if(idx != -1) return idx;

    if(g->node_count == g->capacity){
        // 检查 capacity 是否足够，不够需要 realloc
        int new_capacity = g->capacity * 2;
        VertexNode* new_nodes = (VertexNode*)realloc(g->nodes, new_capacity * sizeof(VertexNode));
        if(new_nodes == NULL){
            fprintf(stderr, "Error: Failed to allocate bigger memory for graph nodes.\n");
            return -1; 
        }
        g->nodes = new_nodes;
        g->capacity = new_capacity; 
    }

    // 初始化vertexnode
    strcpy(g->nodes[g->node_count].ip_addr, ip);
    g->nodes[g->node_count].head_edge = NULL;
    g->nodes[g->node_count].head_inedge = NULL;

    g->nodes[g->node_count].degree = 0;
    g->nodes[g->node_count].select_degree = 0;

    g->nodes[g->node_count].select_recv_bytes = 0;
    g->nodes[g->node_count].select_send_bytes = 0;
    g->nodes[g->node_count].total_send_bytes = 0;
    g->nodes[g->node_count].total_recv_bytes = 0;

    g->nodes[g->node_count].select_send_ratio = 0;
    g->nodes[g->node_count].send_ratio = 0;
    
    return g->node_count++;
}

// 根据记录统计出节点和边的数据，新建节点和边，并通过邻接表建立联系
bool connect_vertex(PacketRecord* record) {
    // 先找找是否已经存在ip对应的节点
    int src_idx = add_node(record->src_ip); 
    int dst_idx = add_node(record->dst_ip);
    if(src_idx == -1 || dst_idx == -1){ // 返回-1表示添加失败，正常应该直接返回找到的下标或者新建的下标
        return false;
    }

    // 统计节点的总流量
    g->nodes[src_idx].total_send_bytes += record->data_size;
    g->nodes[dst_idx].total_recv_bytes += record->data_size;

    // 1. 查找是否已经存在 A -> B 的正向边
    EdgeNode* fwd_edge = g->nodes[src_idx].head_edge;
    while(fwd_edge){
        if(fwd_edge->dst_idx == dst_idx){
            // 找到正向边，合并记录和统计量
            fwd_edge->tail_record->next_record = record; 
            fwd_edge->tail_record = record; 
            fwd_edge->total_edge_bytes += record->data_size;
            fwd_edge->total_edge_duration += record->duration;
            fwd_edge->total_record++;

            // 同步更新 B 的入度边 (head_inedge) 的统计量
            EdgeNode* in_edge = g->nodes[dst_idx].head_inedge;
            while(in_edge){
                if(in_edge->src_idx == src_idx){ // 找到对应的入边
                    in_edge->total_edge_bytes += record->data_size;
                    in_edge->total_edge_duration += record->duration;
                    in_edge->total_record++;
                    break;
                }
                in_edge = in_edge->next_edge;
            }
            return true;
        }
        fwd_edge = fwd_edge->next_edge;
    }

    // 2. 走到这里，说明是一条全新的 A -> B 的连接
    // 检查反向边 (B -> A) 是否存在，决定是否增加度数 (degree)
    bool reverse_exists = false;
    EdgeNode* rev_edge = g->nodes[dst_idx].head_edge;
    while(rev_edge){
        if(rev_edge->dst_idx == src_idx){
            reverse_exists = true;
            break;
        }
        rev_edge = rev_edge->next_edge;
    }

    if(!reverse_exists){ // 如果 B -> A 不存在，那么就是全新的A和B的连接，加degree（每次都在新建连接时加degree）
        g->nodes[src_idx].degree++;
        g->nodes[dst_idx].degree++;
    }

    // 3. 创建 A 的出度边 (正向边)
    EdgeNode* new_fwd = (EdgeNode*)malloc(sizeof(EdgeNode));
    new_fwd->src_idx = src_idx;
    new_fwd->dst_idx = dst_idx;
    new_fwd->total_edge_bytes = record->data_size;
    new_fwd->total_edge_duration = record->duration;
    new_fwd->total_record = 1;
    new_fwd->select_edge_bytes = 0; // select系列先初始化为0
    new_fwd->select_edge_duration = 0;
    new_fwd->select_record = 0;
    new_fwd->head_record = record;
    new_fwd->tail_record = record;
    // 头插 new_fwd
    new_fwd->next_edge = g->nodes[src_idx].head_edge; 
    g->nodes[src_idx].head_edge = new_fwd;

    // 4. 创建 B 的入度边
    EdgeNode* new_in = (EdgeNode*)malloc(sizeof(EdgeNode));
    new_in->src_idx = src_idx;
    new_in->dst_idx = dst_idx;
    new_in->total_edge_bytes = record->data_size;
    new_in->total_edge_duration = record->duration;
    new_in->total_record = 1;
    new_in->select_edge_bytes = 0;
    new_in->select_edge_duration = 0;
    new_in->select_record = 0;
    
    // 入度边不挂载 PacketRecord 链表，防止释放内存时 double-free！
    new_in->head_record = NULL; 
    new_in->tail_record = NULL;
    
    new_in->next_edge = g->nodes[dst_idx].head_inedge;
    g->nodes[dst_idx].head_inedge = new_in;

    return true;
}

void init_select(){
    // 初始化所有节点，以及边的select变量，默认为total
    for(int i=0; i<g->node_count; i++){ // 第i个节点
        // 设置edge的select变量为total
        EdgeNode *curr_edge = g->nodes[i].head_edge;
        while(curr_edge){
            curr_edge->select_edge_bytes = curr_edge->total_edge_bytes;
            curr_edge->select_edge_duration = curr_edge->total_edge_duration;
            curr_edge->select_record = curr_edge->total_record;
            curr_edge = curr_edge->next_edge;
        }
        // 统计每一个节点的ratio
        long long total = g->nodes[i].total_send_bytes + g->nodes[i].total_recv_bytes;
        g->nodes[i].send_ratio = (double)g->nodes[i].total_send_bytes / total;
        // 设置vertex的select变量为total
        g->nodes[i].select_send_ratio = g->nodes[i].send_ratio;
        g->nodes[i].select_degree = g->nodes[i].degree;
        g->nodes[i].select_send_bytes = g->nodes[i].total_send_bytes;
        g->nodes[i].select_recv_bytes = g->nodes[i].total_recv_bytes;
    }
}

// 参数说明：若 ip 为 "-" 表示不筛选 IP，若 port 为 -1 表示不筛选端口
void apply_filter(const char* any_ip, const char* src_ip, const char* dst_ip, int src_port, int dst_port, int tcp, int udp, int icmp, int other) {
    // 1. 清零所有节点的 select 统计
    for(int i=0; i<g->node_count; i++) {
        g->nodes[i].select_send_bytes = 0;
        g->nodes[i].select_recv_bytes = 0;
        g->nodes[i].select_send_ratio = 0.0;
        g->nodes[i].select_degree = 0;
    }

    // 2. 遍历边和记录，进行重新统计
    for(int i=0; i<g->node_count; i++){
        EdgeNode* edge = g->nodes[i].head_edge;
        while(edge){
            // 清零所有边的 select 统计
            edge->select_edge_bytes = 0;
            edge->select_edge_duration = 0.0;
            edge->select_record = 0;
            
            PacketRecord* rec = edge->head_record;
            while(rec){
                bool match = true;
                
                // 叠加筛选逻辑
                if (strcmp(any_ip, "-") != 0) {
                    if (strcmp(rec->src_ip, any_ip) != 0 && strcmp(rec->dst_ip, any_ip) != 0) {
                        match = false; // 如果都不等于，则不匹配
                    }
                }
                if (strcmp(src_ip, "-") != 0 && strcmp(rec->src_ip, src_ip) != 0) match = false; // 如果传了值，而且record值和传的值不相等，那不显示
                if (strcmp(dst_ip, "-") != 0 && strcmp(rec->dst_ip, dst_ip) != 0) match = false;
                if (src_port != -1 && rec->src_port != src_port) match = false;
                if (dst_port != -1 && rec->dst_port != dst_port) match = false;
                
                if (rec->protocol == 6 && tcp == 0) match = false; // 如果这条记录等于6，但是tcp没打勾，那不显示
                if (rec->protocol == 17 && udp == 0) match = false;
                if (rec->protocol == 1 && icmp == 0) match = false;
                if (rec->protocol != 6 && rec->protocol != 17 && rec->protocol != 1 && other == 0) match = false;

                // 记录当前 Record 的命运
                rec->is_selected = match;

                // 如果符合条件，累加到边和节点 select 统计里
                if(match){
                    edge->select_edge_bytes += rec->data_size;
                    edge->select_edge_duration += rec->duration;
                    edge->select_record++;
                    g->nodes[edge->src_idx].select_send_bytes += rec->data_size;
                    g->nodes[edge->dst_idx].select_recv_bytes += rec->data_size;
                }
                rec = rec->next_record;
            }
            // 如果这条边有符合条件的记录，说明这条边是活跃的，给源和目的节点的 degree 加 1
            /*if(edge->select_record>0){
                g->nodes[edge->src_idx].select_degree++;
                g->nodes[edge->dst_idx].select_degree++;
            }*/
            edge = edge->next_edge;
        }
    }

    // 3. 专门针对无向图的 select_degree 去重计算
    for(int i=0; i < g->node_count; i++){
        EdgeNode* edge = g->nodes[i].head_edge;
        while(edge){
            // 如果这条边在筛选后存活
            if(edge->select_record > 0){
                // 查找它的反向边
                bool reverse_active = false;
                EdgeNode* rev = g->nodes[edge->dst_idx].head_edge;
                while(rev){
                    if(rev->dst_idx == edge->src_idx){
                        // 如果反向边存在且同样存活
                        if(rev->select_record > 0) {
                            reverse_active = true;
                        }
                        break;
                    }
                    rev = rev->next_edge;
                }
                // 去重核心逻辑：
                // 如果没有反向活跃流量，正常 +1。
                // 如果有反向活跃流量，为了避免 A->B 加一次，B->A 又加一次，
                // 我们规定只在处理 src_idx < dst_idx 时才加 1。
                if(!reverse_active || (edge->src_idx < edge->dst_idx)){
                    g->nodes[edge->src_idx].select_degree++;
                    g->nodes[edge->dst_idx].select_degree++;
                }
            }
            edge = edge->next_edge;
        }
    }

    // 4. 最后重新计算一次 send_ratio
    for(int i=0; i<g->node_count; i++){
        long long selected = g->nodes[i].select_send_bytes + g->nodes[i].select_recv_bytes;
        if(g->nodes[i].select_degree&&selected>0){
            g->nodes[i].select_send_ratio = (double)g->nodes[i].select_send_bytes/selected;
        }
    }
}

// 深度释放图的所有内存
void free_graph() {
    if (g == NULL) return;

    for (int i = 0; i < g->node_count; i++) {
        // 1. 释放出度边及其内部的 Record
        EdgeNode* curr_fwd = g->nodes[i].head_edge;
        while (curr_fwd != NULL) {
            EdgeNode* next_fwd = curr_fwd->next_edge;
            
            // 释放挂载的 PacketRecord
            PacketRecord* curr_rec = curr_fwd->head_record;
            while(curr_rec != NULL) {
                PacketRecord* next_rec = curr_rec->next_record;
                free(curr_rec);
                curr_rec = next_rec;
            }
            free(curr_fwd);
            curr_fwd = next_fwd;
        }

        // 2. 释放入度边 (因为我们在 connect_vertex 里设置了它的 record 为 NULL，这里直接释放边即可)
        EdgeNode* curr_in = g->nodes[i].head_inedge;
        while(curr_in != NULL){
            EdgeNode* next_in = curr_in->next_edge;
            free(curr_in);
            curr_in = next_in;
        }
    }

    if (g->nodes != NULL) {
        free(g->nodes);
    }
    free(g);
}