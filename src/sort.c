#include "../include/common.h"
#include "../include/graph.h"
#include "../include/sort.h"

#define VERTEX_MAX 3000
#define EDGE_MAX 3000
#define RECORD_MAX 3000

double ratio_threshold = 0.0; 

bool Vertex_Filter_Change = 0; // 初始化为0
bool Edge_Filter_Change = 0;
bool Record_Filter_Change = 0;

ModeType Mode = Edge; 

// ---------------------  VERTEX  ------------------------

static VertexNode *vertex_sort[VERTEX_MAX] = {0}; 

VertexSortType VertexSortMode = TotalBytes;

static int vertex_count = 0; // 记录筛选后剩下多少个节点

static int compareVertex(const void *a, const void *b){
    VertexNode *V1=*(VertexNode **)a;
    VertexNode *V2=*(VertexNode **)b;

    long long d = 0;
    switch(VertexSortMode){ // 这哥们是全局变量
        case TotalBytes:
            d = (V1->select_send_bytes+V1->select_recv_bytes) - (V2->select_send_bytes+V2->select_recv_bytes);
            break;
        case SendBytes:
            d = (V1->select_send_bytes - V2->select_send_bytes); break;
        case Recvbytes:
            d = (V1->select_recv_bytes - V2->select_recv_bytes); break;
        case Ipaddr:
            return strcmp(V1->ip_addr, V2->ip_addr);
        case Degree:
            d = (V1->degree - V2->degree); 
            break;
    }
    if (d > 0) return -1; // 如果V1>V2，那么传回的是负数，则V1在前，降序
    else if (d==0) return 0;
    else return 1;
}

void SetVertex(){
    // 将符合筛选条件的待排序记录加入数组
    if(!Vertex_Filter_Change && vertex_sort[0] != NULL){ 
        // 其中Vertex_Filter_Change是全局变量
        // vertex_sort[0]如果不等于NULL且用户未改变filter配置，则不用重新加
        return;
    }
    vertex_count = 0; // 重新记录排序记录条数
    // 我们把 graph->nodes 里的每个节点的地址，填入 vertex_sort 数组
    for(int i=0; i < g->node_count; i++){
        if(g->nodes[i].select_degree&&g->nodes[i].select_send_ratio>=ratio_threshold){
            // 遍历每个节点，如果该节点中有筛选后剩下的流量，则加入数组准备排序
            vertex_sort[vertex_count++] = &g->nodes[i];
        }
    }
    Vertex_Filter_Change = 0; // 更新备用
    printf("end SetVertex\n");
}

void PutVertex(VertexSortType VertexSortMode, int count){
    for(int i=0;i<count;i++){
        VertexNode *V = vertex_sort[i];
        printf("%s,%lld,%lld,%lld,%.2lf,%d\n",V->ip_addr, V->select_recv_bytes+V->select_send_bytes, V->select_send_bytes, V->select_recv_bytes, V->select_send_ratio, V->degree);
    }
}

void VertexSort(VertexSortType VertexSortMode){
    // 进行一个排序
    printf("VertexSort Start\n");
    SetVertex(); // 传graph的地址等，初始化数组(如果之前用过就不用再查一遍graph)
    qsort(vertex_sort, vertex_count, sizeof(VertexNode*), compareVertex);
    printf("end qsort\n");
    PutVertex(VertexSortMode, vertex_count);
}

// ---------------------  EDGE  ------------------------

static EdgeNode *edge_sort[EDGE_MAX] = {0};

EdgeSortType EdgeSortMode = EdgeBytes;

static int edge_count = 0; 

static int compareEdge(const void *a, const void *b){
    EdgeNode *E1=*(EdgeNode **)a;
    EdgeNode *E2=*(EdgeNode **)b;

    long long d;
    switch(EdgeSortMode){ // 这哥们是全局变量
        case EdgeBytes:
            d = (E1->select_edge_bytes - E2->select_edge_bytes); break; // 如果E1>E2，那么传回的是负数，则E1在前，降序
        case EdgeRecord:
            d = (E1->select_record - E2->select_record); break;
        case EdgeSrcIP:
            return strcmp(g->nodes[E1->src_idx].ip_addr, g->nodes[E2->src_idx].ip_addr); break;
        case EdgeDstIP:
            return strcmp(g->nodes[E1->dst_idx].ip_addr, g->nodes[E2->dst_idx].ip_addr); break;

    }
    if (d > 0) return -1;
    else if (d == 0) return 0;
    else return 1;
}

void SetEdge(){
    if(!Edge_Filter_Change && edge_sort[0]!=NULL){
        return;
    }
    edge_count = 0;
    for(int i=0; i < g->node_count; i++){
        VertexNode Vi = (g->nodes)[i];
        EdgeNode *p = Vi.head_edge;
        while(p){
            if(p->select_record > 0) { // 只有符合条件的边才加进去
                edge_sort[edge_count++] = p;
            }
            p = p->next_edge;
        }
    }
    Edge_Filter_Change = 0;
    return;
}

void PutEdge(EdgeSortType EdgeSortMode, int count){
    for(int i=0;i<count;i++){
        EdgeNode *E=edge_sort[i];

        // 利用索引去 Graph 的 nodes 数组里找对应的 IP 字符串
        char *src_ip = g->nodes[E->src_idx].ip_addr;
        char *dst_ip = g->nodes[E->dst_idx].ip_addr;

        printf("%s,%s,%lld,%.3lf,%d\n", src_ip, dst_ip, E->select_edge_bytes, E->select_edge_duration, E->select_record);
    }
}

void EdgeSort(EdgeSortType EdgeSortMode){ // 因为选项已经变成全局变量，所以不用传
    // 进行一个排序
    printf("EdgeSort Start\n");
    SetEdge();
    qsort(edge_sort, edge_count, sizeof(EdgeNode*), compareEdge);
    PutEdge(EdgeSortMode, edge_count);
}

// --------------------- RECORD ------------------------

static PacketRecord *record_sort[RECORD_MAX] = {0}; 

RecordSortType RecordSortMode = RecordBytes;

static int record_count = 0; // 全局记录实际的 Record 总条数

// 比较函数：默认按流量大小降序排序
static int compareRecord(const void *a, const void *b){
    PacketRecord *R1 = *(PacketRecord **)a;
    PacketRecord *R2 = *(PacketRecord **)b;
    
    long long d = 0;
    switch(RecordSortMode){
        case SrcIP:
            return strcmp(R1->src_ip, R2->src_ip); break;
        case DstIP:
            return strcmp(R1->dst_ip, R2->dst_ip); break;
        case SrcPort:
            d = R1->src_port - R2->src_port; break;
        case DstPort:
            d = R1->dst_port - R2->dst_port; break;
        case RecordBytes:
            d = R1->data_size - R2->data_size;
            if (d > 0) return -1;       // 降序
            else if (d == 0) return 0;
            else return 1;
        case RecordDuration:{
            double dur = R1->duration - R2->duration;
            if (dur > 0) return -1;       // 降序
            else if (dur == 0) return 0;
            else return 1;
        }
    }
    if (d > 0) return 1;       // 升序
    else if (d == 0) return 0;
    else return -1;
}

void SetRecord(){
    if(!Record_Filter_Change && record_sort[0] != NULL){
        return; // 如果已经初始化过，直接跳过
    }
    // 遍历所有顶点
    record_count = 0;
    for(int i = 0; i < g->node_count; i++){
        EdgeNode *edge = g->nodes[i].head_edge;
        // 遍历顶点连出去的所有边
        while(edge){
            PacketRecord *rec = edge->head_record;
            // 遍历边里面挂载的所有 Record 链表
            while(rec){
                if(rec->is_selected) { // 只有被打标的记录才加进去
                    record_sort[record_count++] = rec;
                }
                rec = rec->next_record;
            }
            edge = edge->next_edge;
        }
    }
    Record_Filter_Change = 0;
}

void PutRecord(int count){
    for(int i = 0; i < count; i++){
        PacketRecord *R = record_sort[i];
        // 打印格式：源IP, 目的IP, 协议, 源端口, 目的端口, 数据大小, 持续时间
        printf("%s,%s,%d,%d,%d,%lld,%.3lf\n", 
            R->src_ip, R->dst_ip, R->protocol, 
            R->src_port, R->dst_port, R->data_size, R->duration);
    }
}

void RecordSort(){
    SetRecord();
    qsort(record_sort, record_count, sizeof(PacketRecord*), compareRecord);
    PutRecord(record_count);
}


