#ifndef __SOFTIRQS_H__
#define __SOFTIRQS_H__

#define MAX_SLOTS 20

struct hist {
    u32 slots[MAX_SLOTS];
};

#endif