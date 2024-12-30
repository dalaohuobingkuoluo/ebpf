#ifndef __RUNQLAT_H__
#define __RUNQLAT_H__

#define MAX_SLOTS 26
#define TASK_COMM_LEN 16

struct hist{
    u32 slots[MAX_SLOTS];
    char comm[TASK_COMM_LEN];
};

#endif