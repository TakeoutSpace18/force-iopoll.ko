# force-iopoll.ko
This is a Linux kernel module to force polled I/O path on NVMe SSDs.\
Polled I/O path allows to reduce read latency on modern low-latency SSDs. Speedup is achived by getting rid of OS context switch and interrupt handling overhead, but with cost of high CPU utilization. 

Currently, polled I/O path in Linux is only accessible via io_uring without page cache (with `O_DIRECT` flag). Synchronous direct polled I/O path was [removed](https://patchwork.kernel.org/project/linux-mm/patch/20220420143110.2679002-1-ming.lei@redhat.com/#24824449) since kernel 5.19.

This module enables polled I/O path for every NVMe SSD read for given process. It intercepts `submit_bio` call on the block layer and injects `REQ_POLLED` flag, later polling for bio completion with `bio_poll`.

**Note:** module is not thoroughly tested, so stable work is not guaranteed.

### Add poll queues to NVMe driver

In order for polling to work, you should set nvme.poll_queues driver parameter before the disks are attached. You can do it by inserting `nvme.poll_queues=n` to kernel command line, where `n` is the number of queues you want. 

### Configuration
Module is configured through `/proc/force_iopoll_config`file.\
**Note:** Don't edit with vim, cause it fails with fsync error. Use echo.

Example configuration:
```
# force_iopoll configuration
# Format: <pid> [flags=follow_forks]
# Flags:
# 	follow_forks - enable polling for forked processes

9588 flags=follow_forks
3881
8621 flags=follow_forks
```

### Benchmark results
Tested on HUAWEI Matebook 14s HKFG-X, i7-13700H, 16Gb RAM.\
Fio random read of 160Gb file on SSD, sync read latency reduction - near 16%.
![sync read latency benchmark](images/sync_read_latency.png)
![mmap read latency benchmark](images/mmap_read_latency.png)
Image below compares in-kernel io_uring polling with sync polling enabled by module.
![io_uring vs module benchmark](images/sync_vs_uring_read_latency.png)
![multithread benchmark](images/multithread.png)
![multithread polled benchmark](images/multithread_polled.png)
