#ifndef __EXECSNOOP_H__
#define __EXECSNOOP_H__

#define TASK_COMM_LEN 16

struct event{
    int pid;
    int ppid;
    int uid;
    bool is_exit;
    char comm[TASK_COMM_LEN];
};

#endif