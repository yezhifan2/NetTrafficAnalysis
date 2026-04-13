#include "../include/common.h"
#include "../include/file_io.h"
#include "../include/graph.h"
#include "../include/sort.h"
#include "../include/extensionpack_path.h"
#include "../include/extensionpack_star.h"
#include "../include/extensionpack_visualize.h"
#include "../include/extensionpack_security.h"

void decode_instruction(char *instruction){
    // printf("%s\n", instruction);
    switch(instruction[0]){
        case 'F':{ // Filter 功能
            char any_ip[32], s_ip[32], d_ip[32];
            int s_p, d_p, t, u, i, o;
            // 匹配格式: F any_ip src_ip dst_ip src_port dst_port tcp udp icmp other
            sscanf(instruction, "F %s %s %s %d %d %d %d %d %d", any_ip, s_ip, d_ip, &s_p, &d_p, &t, &u, &i, &o);
            
            // 1. 应用过滤规则，重写所有的 select_ 变量
            apply_filter(any_ip, s_ip, d_ip, s_p, d_p, t, u, i, o);
            
            Vertex_Filter_Change = 1; // 用这个标志位触发强制刷新，三个都刷新
            Edge_Filter_Change = 1;
            Record_Filter_Change = 1;
        } break;

        case 'K':{// 如果传的指令是key的话，就是说更改默认排序方式
            switch(Mode){
                case Vertex: 
                    if(VertexSortMode == instruction[1]-48) return; // 如果key没变，那么不用刷新排序
                    VertexSortMode = instruction[1]-48;
                    break;
                case Edge: 
                    if(EdgeSortMode == instruction[1]-48) return;
                    EdgeSortMode = instruction[1]-48; 
                    break;
                case Record:
                    if(RecordSortMode == instruction[1]-48) return;
                    RecordSortMode = instruction[1]-48; 
                    break;
            }
        } break;

        case 'M':{ // Mode 功能
            // printf("caseM\n");
            if(Mode == instruction[1]-48) return; // 没改mode就不刷新
            Mode = instruction[1]-48; 
        } break;

        case 'R':{ // Ratio 功能
            // atof 可以把字符串 "0.8" 变成 double 类型的 0.8
            ratio_threshold = atof(instruction + 1); 
            Vertex_Filter_Change = 1; // ratio change也触发重新筛选
        } break;

        case 'P':{ // Path_Find
            char src_ip[32], dst_ip[32];
            // 解析指令，例如 "P 192.168.1.1 10.0.0.1"
            if(sscanf(instruction, "P %s %s", src_ip, dst_ip) == 2){
                // 调用路径查找函数
                find_and_print_paths(g, src_ip, dst_ip);
            }
            else printf("解析 IP 错误，格式应为: P源IP,目的IP\n");
        } return; // 直接跳出函数，因为此功能不触发函数最后的重新排序

        case 'S':{ // Star_Detect
            int star_num;
            // 解析指令，例如 "S 20"
            if(sscanf(instruction, "S %d", &star_num)){
                detect_star(g, star_num);
            }
            else printf("解析指令错误，格式应为: S 20\n");
        } return;

        case 'C': { // Check_Security
            char ip1[32], ip2[32], ip3[32];
            int action;
            // 解析指令 C 192.168.1.1 10.0.0.1 10.0.0.255 0
            if(sscanf(instruction, "C %s %s %s %d", ip1, ip2, ip3, &action) == 4){
                check_security_rule(g, ip1, ip2, ip3, action);
            } 
            else printf("解析安全规则错误\n");
        } return;

        case 'V': { // Visualize_Graph
            char target_ip[32];
            // 解析指令 V 192.168.1.1
            if(sscanf(instruction, "V %s", target_ip) == 1){
                visualize_subgraph(g, target_ip);
            } 
            else printf("解析子图IP错误\n");
        } return; 

    }
    // 处理完instruction[0]后，进行排序
    switch(Mode){
        case Vertex: 
            VertexSort(VertexSortMode);
            break;
        case Edge: 
            EdgeSort(EdgeSortMode);
            break;
        case Record:
            RecordSort();
            break;
    }
}

int main(int argc, char *argv[]){

    // 启用无缓冲模式，防止输出卡在缓冲区
    setvbuf(stdout, NULL, _IONBF, 0); 
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("[C-Debug] 进程已启动...\n");

    // 1. 加载数据 √
    if(argc < 2){
        SEND_ERROR();
        return 1; // 返回非零值表示出错
    }
    // 我想要用户自己来选择文件，通过GUI的文件浏览选择文件，再把文件名传给main，进行文件读取
    const char* input_file = argv[1]; 
    printf("[C-Debug] 收到文件路径: %s\n", input_file); // 打印收到的路径，检查乱码

    // 开始录入数据
    int record_count=0;
    printf("[C-Debug] 正在调用 load_data...\n");
    PacketRecord* records=load_data(input_file, &record_count); // records指向传回的指针（若干行记录的开头）
    if(!records){
        printf("Error: Failed to load data.\n");
        return 1;
    }
    printf("成功读取 %d 条记录\n", record_count);

    // 2. 构建节点与边的图，进行初步统计 √
    g=init_graph(1000); // 初始容量1000
    bool build_success = true;
    for(int i = 0; i < record_count; i++){
        // 每处理 100 条打印一次，证明没死循环
        if (i % 100 == 0) {
             printf("[C-Debug] 正在处理第 %d/%d 条...\n", i, record_count);
        }
        if(!connect_vertex(&records[i])){
            build_success = false;
            printf("[C-Error] 第 %d 条记录构建图失败\n", i);
            break; // 如果有一个失败，就停止
        }
    }
    if(build_success){ // 标志成功建立完整个图
        printf("图构建完成，包含 %d 个节点\n", g->node_count);
        init_select(); // 把节点和边的select变量（筛选）都init为total
        printf("初始化完成，等待指令\n");
        SEND_END(); // 这里回馈已经初始化完成
    }
    else{
        printf("Error: 图构建失败 (内存不足或逻辑错误)\n");
        // 如果构建失败，建议退出，否则后面会崩
        return 1; 
    }

    // 3. 循环接受指令
    char instruction[100];
    while(fgets(instruction, sizeof(instruction), stdin)!=NULL){
        size_t len = strlen(instruction);
        instruction[len-1] = '\0'; // 将换行符替换为字符串结束符
        printf("C 收到: %s\n", instruction); // 打印收到的指令
        // 解析收到的指令
        decode_instruction(instruction);
        SEND_END(); // 这里回馈数据已经传送完毕
    }

    // 4. 释放内存
    // 释放连续分配的记录数组
    if (records != NULL) {
        free(records);
    }
    // 深度释放图结构（边链表 -> 节点数组 -> 图本身）
    if (g != NULL) {
        free_graph();
    }
    printf("[C-Debug] 内存清理完成，进程安全退出。\n");

    return 0;
}