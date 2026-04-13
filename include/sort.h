#ifndef SORT_H
#define SORT_H

#include "common.h"

// sort 顶部定义一个全局的筛选阈
extern double ratio_threshold; 

//再来三个全局的筛选更改标志
extern bool Vertex_Filter_Change;
extern bool Edge_Filter_Change;
extern bool Record_Filter_Change;

extern ModeType Mode; 

// ---------------------  VERTEX  ------------------------

extern VertexSortType VertexSortMode;

void SetVertex();

void PutVertex(VertexSortType VertexSortMode, int count);

void VertexSort(VertexSortType VertexSortMode);

// ---------------------  EDGE  ------------------------

extern EdgeSortType EdgeSortMode;

void SetEdge();

void PutEdge(EdgeSortType EdgeSortMode, int count);

void EdgeSort(EdgeSortType EdgeSortMode);

// --------------------- RECORD ------------------------

extern RecordSortType RecordSortMode;

extern int global_record_count;

void SetRecord();

void PutRecord(int count);

void RecordSort();

#endif