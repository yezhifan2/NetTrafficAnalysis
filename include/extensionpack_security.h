#ifndef SECURITY_H
#define SECURITY_H
#include "common.h"

unsigned int ip_to_int(const char* ip);

void check_security_rule(Graph* g, const char* ip1, const char* ip2, const char* ip3, int action);

#endif