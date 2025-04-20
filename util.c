#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "util.h"

#include <linux/blk_types.h>
#include <linux/tracepoint.h>
#include <linux/kprobes.h>

struct find_tracepoint_arg
{
    const char *name;
    struct tracepoint *result;
};

static void find_tracepoint_cb(struct tracepoint *tp, void *priv)
{
    struct find_tracepoint_arg *arg = (struct find_tracepoint_arg *) priv;
    if (strcmp(tp->name, arg->name) == 0) {
        arg->result = tp;
    }
}

struct tracepoint *find_tracepoint(const char *name)
{
    struct find_tracepoint_arg arg;
    arg.name = name;
    arg.result = NULL;

    for_each_kernel_tracepoint(find_tracepoint_cb, &arg);

    return arg.result;
}

unsigned long kprobe_lookup(const char *symbol_name)
{
    struct kprobe kp;

    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = symbol_name;
    if (register_kprobe(&kp) < 0) {
        pr_err("Failed to kprobe lookup %s\n", symbol_name);
        return 0;
    }

    unregister_kprobe(&kp);
    return (unsigned long)kp.addr;
}

void __maybe_unused print_bio_bi_opf(blk_opf_t bi_opf)
{
    enum req_op op = bi_opf & REQ_OP_MASK;
    
    switch (op) {
        case REQ_OP_READ:           printk(KERN_INFO "OP_READ"); break;
        case REQ_OP_WRITE:          printk(KERN_INFO "OP_WRITE"); break;
        case REQ_OP_FLUSH:          printk(KERN_INFO "OP_FLUSH"); break;
        case REQ_OP_DISCARD:        printk(KERN_INFO "OP_DISCARD"); break;
        case REQ_OP_SECURE_ERASE:   printk(KERN_INFO "OP_SECURE_ERASE"); break;
        case REQ_OP_ZONE_APPEND:    printk(KERN_INFO "OP_ZONE_APPEND"); break;
        case REQ_OP_WRITE_ZEROES:   printk(KERN_INFO "OP_WRITE_ZEROES"); break;
        case REQ_OP_ZONE_OPEN:      printk(KERN_INFO "OP_ZONE_OPEN"); break;
        case REQ_OP_ZONE_CLOSE:     printk(KERN_INFO "OP_ZONE_CLOSE"); break;
        case REQ_OP_ZONE_FINISH:    printk(KERN_INFO "OP_ZONE_FINISH"); break;
        case REQ_OP_ZONE_RESET:     printk(KERN_INFO "OP_ZONE_RESET"); break;
        case REQ_OP_ZONE_RESET_ALL: printk(KERN_INFO "OP_ZONE_RESET_ALL"); break;
        case REQ_OP_DRV_IN:         printk(KERN_INFO "OP_DRV_IN"); break;
        case REQ_OP_DRV_OUT:        printk(KERN_INFO "OP_DRV_OUT"); break;
        default:                    printk(KERN_INFO "OP_UNKNOWN(%u)", op); break;
    }
    
    if (bi_opf & REQ_FAILFAST_DEV)      printk(KERN_CONT " FAILFAST_DEV");
    if (bi_opf & REQ_FAILFAST_TRANSPORT) printk(KERN_CONT " FAILFAST_TRANSPORT");
    if (bi_opf & REQ_FAILFAST_DRIVER)   printk(KERN_CONT " FAILFAST_DRIVER");
    if (bi_opf & REQ_SYNC)              printk(KERN_CONT " SYNC");
    if (bi_opf & REQ_META)              printk(KERN_CONT " META");
    if (bi_opf & REQ_PRIO)              printk(KERN_CONT " PRIO");
    if (bi_opf & REQ_NOMERGE)           printk(KERN_CONT " NOMERGE");
    if (bi_opf & REQ_IDLE)              printk(KERN_CONT " IDLE");
    if (bi_opf & REQ_INTEGRITY)         printk(KERN_CONT " INTEGRITY");
    if (bi_opf & REQ_FUA)               printk(KERN_CONT " FUA");
    if (bi_opf & REQ_PREFLUSH)          printk(KERN_CONT " PREFLUSH");
    if (bi_opf & REQ_RAHEAD)            printk(KERN_CONT " RAHEAD");
    if (bi_opf & REQ_BACKGROUND)        printk(KERN_CONT " BACKGROUND");
    if (bi_opf & REQ_NOWAIT)            printk(KERN_CONT " NOWAIT");
    if (bi_opf & REQ_POLLED)            printk(KERN_CONT " POLLED");
    if (bi_opf & REQ_ALLOC_CACHE)       printk(KERN_CONT " ALLOC_CACHE");
    if (bi_opf & REQ_SWAP)              printk(KERN_CONT " SWAP");
    if (bi_opf & REQ_DRV)               printk(KERN_CONT " DRV");
    if (bi_opf & REQ_FS_PRIVATE)        printk(KERN_CONT " FS_PRIVATE");
    if (bi_opf & REQ_NOUNMAP)           printk(KERN_CONT " NOUNMAP");

    printk(KERN_CONT "\n");
}
