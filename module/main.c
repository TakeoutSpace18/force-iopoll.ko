#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>

#include "linux/force_iopoll.h"
#include "ftrace_hook.h"
#include "config.h"
#include "util.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Urdin");
MODULE_DESCRIPTION("A module to enable polled I/O path on nvme devices");
MODULE_VERSION("0.1");

/* disable tail call optimization to avoid bug in ftrace hooked function
 * (see the end of https://habr.com/ru/articles/413241/) */
#pragma GCC optimize("-fno-optimize-sibling-calls")

/* bio context for force_iopoll module */
struct force_iopoll_bio_ctx
{
    bio_end_io_t *orig_bi_end_io;
    void *orig_bi_private;
    uint64_t iopoll_start;
    bool done;
};


static bool bio_is_empty(struct bio *bio)
{
    return bio->bi_iter.bi_size == 0;
}

static void examine_iob(struct io_comp_batch *iob)
{
    int count = 0;
    struct request *req;
    rq_list_for_each(&iob->req_list, req) {
        count++;
	}

    pr_alert_ratelimited("io_comp_batch size: %i", count);
}

/* Is called upon bio completion. Restores modifications made to bio
 * by this module and calls original completion callback. */
static void force_iopoll_endio(struct bio *bio)
{
    struct force_iopoll_bio_ctx *ctx = bio->bi_private;
    ctx->done = true;

    /* restore original bio state */
    bio_clear_polled(bio);
    bio->bi_end_io = ctx->orig_bi_end_io;
    bio->bi_private = ctx->orig_bi_private;

    ctx->orig_bi_end_io(bio);
}

static int iopoll_classic(struct bio *bio, struct io_comp_batch *iob)
{
    int ret;

    ret = bio_poll(bio, iob, 0);
    if (ret == 0) {
        pr_alert_ratelimited("bio_poll() returned 0 [%s]\n", current->comm);
    }

    return ret;
}

static u64 hybrid_poll_time = LLONG_MAX;

static u64 hybrid_iopoll_delay(void)
{
	struct hrtimer_sleeper timer;
	enum hrtimer_mode mode;
	ktime_t kt;
	u64 sleep_time;

	if (hybrid_poll_time == LLONG_MAX)
		return 0;

	/* Using half the running time to do schedule */
	sleep_time = hybrid_poll_time / 2;

	kt = ktime_set(0, sleep_time);

	mode = HRTIMER_MODE_REL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
	hrtimer_setup_sleeper_on_stack(&timer, CLOCK_MONOTONIC, mode);
#else
    hrtimer_init_sleeper_on_stack(&timer, CLOCK_MONOTONIC, mode);
#endif

	hrtimer_set_expires(&timer.timer, kt);
	set_current_state(TASK_INTERRUPTIBLE);
	hrtimer_sleeper_start_expires(&timer, mode);

	if (timer.task)
		io_schedule();

	hrtimer_cancel(&timer.timer);
	__set_current_state(TASK_RUNNING);
	destroy_hrtimer_on_stack(&timer.timer);
	return sleep_time;
}

static int iopoll_hybrid(struct bio *bio, struct io_comp_batch *iob)
{
    struct force_iopoll_bio_ctx *bio_ctx = bio->bi_private;
    uint64_t runtime, sleep_time;
    int ret;

    bio_ctx->iopoll_start = ktime_get_ns();

    sleep_time = hybrid_iopoll_delay();
    ret = iopoll_classic(bio, iob);
    runtime = ktime_get_ns() - bio_ctx->iopoll_start - sleep_time;

	if (hybrid_poll_time > runtime)
		hybrid_poll_time = runtime;

    return ret;
}

/* submit bio and poll for completion inplace */
static void submit_bio_poll(struct bio *bio, bool hybrid)
{
    struct force_iopoll_bio_ctx bio_ctx = {
        .orig_bi_end_io = bio->bi_end_io,
        .orig_bi_private = bio->bi_private,
        .done = false
    };

    bio->bi_opf |= REQ_POLLED;
    bio->bi_private = &bio_ctx;
    bio->bi_end_io = force_iopoll_endio;

    submit_bio(bio);

    /* If submit_bio is called between blk_start_plug() and blk_finish_plug(),
     * io request can be delayed for better merging capability. This causes
     * bio_poll() to hang because bio->bi_cookie that contains request queue
     * number is set at actual request start in function blk_mq_start_request().
     * So finish plug before bio_poll() to avoid this.
     *
     * NOTE: blk_flush_plug() is also called inside bio_poll,
     * but it happens after the read of bi_cookie from bio,
     * so cookie value in bio_poll becomes outdated. */

    if (current->plug != NULL)
        blk_finish_plug(current->plug);

    do {
        if (hybrid) {
            iopoll_hybrid(bio, NULL);
        } else {
            iopoll_classic(bio, NULL);
        }

    } while (!bio_ctx.done);
}

static asmlinkage void submit_bio_interceptor(struct bio *bio)
{
    int flags = 0;
    if (!config_pid_iopoll_enabled(current->pid, &flags) && !config_global_iopoll_enabled(&flags))
        return submit_bio(bio);

    /* Poll only READ operations for now. WRITE needs debugging. */
    if (bio_op(bio) != REQ_OP_READ)
        return submit_bio(bio);

    struct block_device *bdev = READ_ONCE(bio->bi_bdev);
    struct request_queue *q = bdev_get_queue(bdev);

    /* poll support flag moved to queue limits since version 6.11 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
    if (unlikely(!(q->limits.features & BLK_FEAT_POLL))) {
#else
    if (unlikely(!test_bit(QUEUE_FLAG_POLL, &q->queue_flags))) {
#endif
        pr_warn_ratelimited("poll attempt at non-poll queue");
        return submit_bio(bio);
    }

    /* Flush bio execution is double buffered (described in block/blk-flush.c),
     * so avoid polling for it since bio cookie will not be set immediately. */
    if (unlikely(op_is_flush(bio->bi_opf))) {
        pr_warn_ratelimited("flush bio, don't inject REQ_POLLED\n");
        return submit_bio(bio);
    }

    /* TODO: remove ?*/
    // if (bio_is_empty(bio)) {
    //     pr_warn_ratelimited("bio empty, don't inject REQ_POLLED\n");
    //     return submit_bio(bio);
    // }

    return submit_bio_poll(bio, flags & FORCE_IOPOLL_FLAG_HYBRID);
}

struct ftrace_hook submit_bio_hook;
static struct tracepoint *tp_sched_process_fork;
static struct tracepoint *tp_sched_process_exit;

static void sched_process_fork_probe(void *data, struct task_struct *parent,
                                     struct task_struct *child)
{
    int flags;
    if (config_pid_iopoll_enabled(parent->pid, &flags) &&
        (flags & FORCE_IOPOLL_FLAG_FOLLOW_FORKS)) {
        config_add_pid(child->pid, flags);
    }
}

static void sched_process_exit_probe(void *data, struct task_struct *task)
{
    if (config_pid_iopoll_enabled(task->pid, NULL)) {
        config_remove_pid(task->pid);
    }
}

union ioctl_params
{
    struct force_iopoll_addprocess_params addprocess;
    struct force_iopoll_removeprocess_params removeprocess;
    struct force_iopoll_enableglobal_params enableglobal;
};

static long force_iopoll_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    union ioctl_params params;

    switch (cmd) {
        case FORCE_IOPOLL_IOCTL_ADDPROCESS:
            if (copy_from_user(&params.addprocess,
                               (struct force_iopoll_addprocess_params *)arg,
                               sizeof(struct force_iopoll_addprocess_params))) {
                return -EFAULT;
            }

            return config_add_pid(params.addprocess.pid, params.addprocess.flags);

        case FORCE_IOPOLL_IOCTL_REMOVEPROCESS:
            if (copy_from_user(&params.removeprocess,
                               (struct force_iopoll_removeprocess_params *)arg,
                               sizeof(struct force_iopoll_removeprocess_params))) {
                return -EFAULT;
            }

            return config_remove_pid(params.removeprocess.pid);

        case FORCE_IOPOLL_IOCTL_ENABLEGLOBAL:
            if (copy_from_user(&params.enableglobal,
                               (struct force_iopoll_enableglobal_params *)arg,
                               sizeof(struct force_iopoll_enableglobal_params))) {
                return -EFAULT;
            }

            return config_enable_global(params.enableglobal.flags);

        case FORCE_IOPOLL_IOCTL_DISABLEGLOBAL:
            return config_disable_global();

        default:
            return -EINVAL;
    }
}

static const struct file_operations force_iopoll_fops = {
    .unlocked_ioctl = force_iopoll_ioctl,
};

static dev_t first;
static struct class *class;
static struct cdev cdev;

#define FORCE_IOPOLL_CDEV_NAME "force_iopoll"

static int __init force_iopoll_init(void)
{
    config_init();

    if (alloc_chrdev_region(&first, 0, 1, FORCE_IOPOLL_CDEV_NAME) < 0) {
        goto out;
    }

    if ((class = class_create("force_iopoll")) == NULL) {
        goto out_unregister_chrdev_region;
    }

    if (device_create(class, NULL, first, NULL, FORCE_IOPOLL_CDEV_NAME) == NULL) {
        goto out_class_destroy;
    }

    cdev_init(&cdev, &force_iopoll_fops);
    if (cdev_add(&cdev, first, 1) == -1) {
        goto out_device_destroy;
    }

    /* register probes needed for FLAG_FOLLOW_FORKS */
    tp_sched_process_fork = find_tracepoint("sched_process_fork");
    tracepoint_probe_register(tp_sched_process_fork, sched_process_fork_probe, NULL);

    tp_sched_process_exit = find_tracepoint("sched_process_exit");
    tracepoint_probe_register(tp_sched_process_exit, sched_process_exit_probe, NULL);

    if (ftrace_hook_install(&submit_bio_hook, submit_bio, submit_bio_interceptor) < 0) {
        goto out_cdev_del;
    }

    pr_info("module loaded\n");
    return 0;

out_cdev_del:
    cdev_del(&cdev);
out_device_destroy:
    device_destroy(class, first);
out_class_destroy:
    class_destroy(class);
out_unregister_chrdev_region:
    unregister_chrdev_region(first, 1);
out:
    return -1;
}

static void __exit force_iopoll_exit(void)
{
    if (ftrace_hook_is_installed(&submit_bio_hook)) {
        ftrace_hook_remove(&submit_bio_hook);
    }

    tracepoint_probe_unregister(tp_sched_process_fork, sched_process_fork_probe, NULL);
    tracepoint_probe_unregister(tp_sched_process_exit, sched_process_exit_probe, NULL);

    cdev_del(&cdev);
    device_destroy(class, first);
    class_destroy(class);
    unregister_chrdev_region(first, 1);

    config_exit();

    pr_info("module unloaded\n");
}

module_init(force_iopoll_init);
module_exit(force_iopoll_exit);
