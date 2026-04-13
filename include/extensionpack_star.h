#ifndef STAR_H
#define STAR_H

#include "common.h"

int judge_star(Graph *g, int idx);

void print_star(Graph *g, int idx, int last_node);
// 主调函数：检测星型结�?
void detect_star(Graph* g, int threshold);

#endif
