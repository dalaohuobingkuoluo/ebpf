#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_include/bits.bpf.h"
#include "../bpf_include/maps.bpf.h"
#include "hardirqs.h"

#define MAX_ENTRY 256

const volatile bool filter_cg = false;
const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile bool do_count = false;

char LICENSE[] SEC("license") = "GPL";

struct irq_key {
	char name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} cgroup_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_ENTRY);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRY);
    __type(key, struct irq_key);
    __type(value, struct info);
} infos SEC(".maps");

static struct info zero;

static int handle_entry(int irq, struct irqaction *action){
    if(filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)){
        return 0;
    }
    if(do_count){
        struct irq_key key = {};
        struct info *info;
        bpf_probe_read_kernel_str(&key.name, sizeof(key.name), BPF_CORE_READ(action, name));
        info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
        if(!info){
            return 0;
        }
        __sync_fetch_and_add(&info->count, 1);
    }else{
        u64 ts = bpf_ktime_get_ns();
        u32 key = 0;
        bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
    }
    return 0;
}

static int handle_exit(int irq, struct irqaction *action){
    if(filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)){
        return 0;
    }
    struct irq_key ikey = {};
    u32 key = 0;
    struct info *info;
    u64 delta, *tsp;
    tsp = bpf_map_lookup_elem(&start, &key);
    if(!tsp){
        return 0;
    }
    delta = bpf_ktime_get_ns() - *tsp;
    if(!targ_ns){
        delta /= 1000u;
    }
    bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), BPF_CORE_READ(action, name));
    info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
    if(!info){
        return 0;
    }
    if(!targ_dist){
        info->count += delta;
    }else{
        u64 slot = log2l(delta);
        if(slot >= MAX_SLOTS){
            slot = MAX_SLOTS - 1;
        }
        info->slots[slot]++; 
    }
    return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action){
    return handle_entry(irq, action);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action){
    return handle_exit(irq, action);
}

SEC("raw_tp/irq_handler_entry")
int BPF_PROG(irq_handler_entry, int irq, struct irqaction *action){
    return handle_entry(irq, action);
}

SEC("raw_tp/irq_handler_exit")
int BPF_PROG(irq_handler_exit, int irq, struct irqaction *action){
    return handle_exit(irq, action);
}



