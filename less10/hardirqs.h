#ifndef __HARDIRQS_H__
#define __HARDIRQS_H__

#define MAX_SLOTS 20
#define MAX_NAME 256

struct info {
    u64 count;
    u32 slots[MAX_SLOTS];
};


#endif