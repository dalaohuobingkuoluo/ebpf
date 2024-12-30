#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

const char LICENSE[] SEC("license") = "GPL";

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret){
    char comm[TASK_COMM_LEN];
    char str[MAX_LINE_SIZE];
    u32 pid;

    if(!ret){
        return 0;
    }
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(str, sizeof(str), ret);
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PID %d(%s) read: %s\n", pid, comm, str);
    return 0;
}