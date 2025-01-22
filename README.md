# Study eBPF

一个记录学习eBPF过程的代码仓库

## How to run

1. 选择一个要执行的ebpf程序cd进去
    ```bash
    cd [dir]
    ```

2. 编译生成ebpf字节码
    ```bash
    go generate
    ```
3. 执行go程序
    ```bash
    go run main.go
    ```

## eBPF Programs
### 01-http-ebpf
使用`bpf_printk`函数打印信息
`cat /sys/kernel/debug/tracing/trace_pipe` 查看打印内容

### 02-tracepoint-open
基于tracepoint静态跟踪点跟踪`sys_enter_openat`函数，并使用`ringbuf`向用户空间输出文件信息。

### 03-trace-open-exit
基于tracepoint静态跟踪点跟踪`sys_enter_openat`以及`sys_exit_openat`函数，使用Hash Map在内核空间中传递信息，并使用`ringbuf`向用户空间输出文件信息。

### http
通过解析以太网帧，IP数据报，TCP数据，监控对应网卡中的http请求，解析并输出日志。