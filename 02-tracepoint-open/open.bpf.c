//go:build ignore
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscall__sys_enter_openat(struct trace_event_raw_sys_enter *ctx){
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    struct event *e = {};

    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) return 0;   // 如果没有分配成功需要退出

    e->pid = pid;
    if (bpf_probe_read_user_str(e->filename, sizeof(e->filename), (const char *)ctx->args[1]) < 0) {
        bpf_ringbuf_discard(e, 0);  // 如果出错需要释放内存
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}