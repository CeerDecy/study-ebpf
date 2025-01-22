//go:build ignore
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct OpenFile {
    u32 pid;
    char filename[256];
} __attribute__((packed));

struct Event {
    u32 pid;
    u64 ret;
    char filename[256];
    char comm[256];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct OpenFile);
} dict SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} rb SEC(".maps");

// find in /sys/kernel/tracing/events
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct OpenFile of = {};
    of.pid = pid;
    if (bpf_probe_read_user_str(of.filename, sizeof(of.filename), (const char *)ctx->args[1]) < 0) {
        return 0;
    }
    bpf_map_update_elem(&dict, &pid, &of, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct OpenFile *of;
    struct Event *e;
    of = bpf_map_lookup_elem(&dict, &pid);
    if (!of) {
        return 0;
    }
    e = bpf_ringbuf_reserve(&rb, sizeof(struct Event), 0);
    if (!e) {
        return 0;
    }

    e->pid = of->pid;
    e->ret = ctx->ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (bpf_probe_read_str(&e->filename, sizeof(e->filename), of->filename) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";