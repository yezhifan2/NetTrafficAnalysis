#ifndef VISUALIZE_H
#define VISUALIZE_H
#include "common.h"

int find_root(int parent[], int i);

void visualize_subgraph(Graph* g, const char* target_ip);

#endif