#ifndef __BOOTSTRAP_H__
#define __BOOTSTRAP_H__

#define TASK_COMM_LEN 16

struct event{
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
};

#endif 