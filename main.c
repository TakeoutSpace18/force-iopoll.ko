#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

#include "ftrace-hook.h"
#include "config.h"
#include "util.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Urdin");
MODULE_DESCRIPTION("A module to enable polled I/O path on nvme devices");
MODULE_VERSION("0.1");

/* disable tail call optimization to avoid bug in ftrace hooked function
 * (see the end of https://habr.com/ru/articles/413241/) */
#pragma GCC optimize("-fno-optimize-sibling-calls")

/* A pointer to original function. Is initialized inside fh_install_hook. */
static asmlinkage void (*orig_submit_bio)(struct bio *bio);

struct endio_hook_data
{
    bio_end_io_t *orig_bi_end_io;
    void *orig_bi_private;
    bool done;
};

/* Is called upon bio completion. Restores modifications made to bio
 * by this module and calls original completion callback. */
static void bio_endio_hook(struct bio *bio)
{
    struct endio_hook_data *hd = bio->bi_private;
    hd->done = true;

    /* restore original bio state */
    bio_clear_polled(bio);
    bio->bi_end_io = hd->orig_bi_end_io;
    bio->bi_private = hd->orig_bi_private;

    hd->orig_bi_end_io(bio);
}

static bool bio_is_empty(struct bio *bio)
{
    return bio->bi_iter.bi_size == 0;
}

/* A function to call submit_bio() and poll for bio completion inplace */
static void submit_bio_poll(struct bio *bio)
{
    struct endio_hook_data hd = {
        .orig_bi_end_io = bio->bi_end_io,
        .orig_bi_private = bio->bi_private,
        .done = false
    };

    bio->bi_opf |= REQ_POLLED;
    bio->bi_private = &hd;
    bio->bi_end_io = bio_endio_hook;

    orig_submit_bio(bio);

    /* If submit_bio is called between blk_start_blug() and blk_finish_plug(), 
     * io request can be delayed for better merging capability. This causes
     * bio_poll() to hang because bio->bi_cookie that contains request queue 
     * number is set at actual request start in function blk_mq_start_request().
     * So finish plug before bio_poll() to avoid this. 
     * TODO: think about a way to save plugging capability */
    if (current->plug)
        blk_finish_plug(current->plug);

    do {
        int ret = bio_poll(bio, NULL, 0);
        if (ret == 0) {
            pr_alert_ratelimited("bio_poll() returned 0 [%s]\n", current->comm);
        }
    } while (!hd.done);

    pr_info_ratelimited("bio completion polled [%s]\n", current->comm);
}

static asmlinkage void fh_submit_bio(struct bio *bio)
{
    if (!config_iopoll_enabled(current->pid, NULL)) {
        return orig_submit_bio(bio);
    }

    /* Poll only READ operations for now. WRITE needs debugging. */
    if (bio_op(bio) != REQ_OP_READ) {
        return orig_submit_bio(bio);
    }

	struct block_device *bdev = READ_ONCE(bio->bi_bdev);
	struct request_queue *q = bdev_get_queue(bdev);
    
    if (unlikely(strncmp(bdev->bd_disk->disk_name, "nvme", 4) != 0)) {
        pr_warn_ratelimited("sumbit_bio() on non nvme device (%s), dont inject REQ_POLLED\n",
                 bdev->bd_disk->disk_name);
        return orig_submit_bio(bio);
    }
    
	if (unlikely(!test_bit(QUEUE_FLAG_POLL, &q->queue_flags))) {
        pr_warn_ratelimited("poll attempt at non-poll queue");
        return orig_submit_bio(bio);
    }

    /* bios with REQ_PREFLUSH and REQ_FUA
     * have complicated logic (described in block/blk-flush.c)
     * and bio cookie (which is mandatory for bio_poll()) is by some reason not set.
     * Needs debugging. */
    if (unlikely(op_is_flush(bio->bi_opf))) {
        pr_warn_ratelimited("flush bio, don't inject REQ_POLLED\n");
        return orig_submit_bio(bio);
    }

    /* TODO: remove ?*/
    if (bio_is_empty(bio)) {
        pr_warn_ratelimited("bio empty, don't inject REQ_POLLED\n");
        return orig_submit_bio(bio);
    }

    return submit_bio_poll(bio);
}

struct ftrace_hook submit_bio_hook =
    HOOK("submit_bio", fh_submit_bio, &orig_submit_bio);

static struct tracepoint *tp_sched_process_fork;
static struct tracepoint *tp_sched_process_exit;

static void sched_process_fork_probe(void *data, struct task_struct *parent,
                                     struct task_struct *child)
{
    unsigned long flags;
    if (config_iopoll_enabled(parent->pid, &flags) && (flags & FLAG_FOLLOW_FORKS)) {
        config_enable_iopoll(child->pid, FLAG_FOLLOW_FORKS);
    }
}

static void sched_process_exit_probe(void *data, struct task_struct *task)
{
    if (config_iopoll_enabled(task->pid, NULL)) {
        config_disable_iopoll(task->pid);
        pr_info("disabled polling for pid %i, process exited [%s]\n", task->pid, task->comm);
    }
}

static int __init force_iopoll_init(void)
{
    pr_info("loading module...\n");
    config_init();

    /* register probes needed for FLAG_FOLLOW_FORKS */
    tp_sched_process_fork = find_tracepoint("sched_process_fork");
    tracepoint_probe_register(tp_sched_process_fork, sched_process_fork_probe, NULL);

    tp_sched_process_exit = find_tracepoint("sched_process_exit");
    tracepoint_probe_register(tp_sched_process_exit, sched_process_exit_probe, NULL);

	fh_install_hook(&submit_bio_hook);

	return 0;
}

static void __exit force_iopoll_exit(void)
{
    pr_info("unloading module...\n");
	if (fh_installed(&submit_bio_hook))
	    fh_remove_hook(&submit_bio_hook);

    tracepoint_probe_unregister(tp_sched_process_fork, sched_process_fork_probe, NULL);
    tracepoint_probe_unregister(tp_sched_process_exit, sched_process_exit_probe, NULL);

    config_exit();
}

module_init(force_iopoll_init);
module_exit(force_iopoll_exit);
