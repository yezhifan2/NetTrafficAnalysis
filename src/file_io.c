#include "../include/file_io.h"
#include "../include/common.h"

// 读取 CSV 文件并返回记录数组
PacketRecord* load_data(const char* filename, int* count){ // packetrecord是一个csv结构体类型，所以这里是一行csv的指针函数

    FILE* file=fopen(filename, "r"); // FILE是预定义的结构体，建立指针file
    if(!file){
        printf("无法打开文件: %s\n", filename);
        return NULL; // 这里就是传回NULL了
    }

    // 已打开文件
    char line[MAX_LINE_LEN]; // 每行读到这个数组里面
    fgets(line, MAX_LINE_LEN, file); // 提前读取一行，跳过表头
    // 分配内存
    int capacity=2000; // 初始2000行
    PacketRecord* records=(PacketRecord*)malloc(sizeof(PacketRecord) * capacity); // records指针指到分配的地址块最前面
    *count=0; // count是一个指针，让指针指向的变量=0

    // 现在开始读取记录
    while(fgets(line, MAX_LINE_LEN, file)){ // 文件还没结束（结束时fgets返回NULL=(void *)0，指针零，而while不管类型，只管值是否0）
        // 检查内存是否满了，满了就扩容
        if (*count >= capacity) {
            capacity *= 2; // 容量翻倍
            PacketRecord* temp = (PacketRecord*)realloc(records, sizeof(PacketRecord) * capacity);
            if (!temp) {
                printf("Error: Memory allocation failed during realloc.\n");
                free(records);
                fclose(file);
                return NULL;
            }
            records = temp;
        }

        // 记录一行数据
        PacketRecord r; // 一行数据的结构体
        // CSV 格式: Source, Destination, Protocol, SrcPort, DstPort, DataSize, Duration
        sscanf(line, "%[^,],%[^,],%d,%d,%d,%lld,%lf", r.src_ip, r.dst_ip, &r.protocol, &r.src_port, &r.dst_port, &r.data_size, &r.duration); 
        r.next_record=NULL; // 初始化指针
        records[*count]=r; // 把局部变量r中的东西录入到graph指向的records里面
        (*count)++; // 让指针指向的值++
    }
    
    //读完，关闭文件
    fclose(file);
    return records; // load_data函数将records指针（开头）传回main文件，读取完成
}