#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/kprobes.h>
#include <linux/utsname.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/ftrace.h>
#include <linux/hashtable.h>

#include "ftrace-hook.h"
#include "kallsyms.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pavel Urdin");
MODULE_DESCRIPTION("A module to enable polling I/O path on ext4");
MODULE_VERSION("0.1");

#pragma GCC optimize("-fno-optimize-sibling-calls")


/* /proc/polled_pids file */
#define PROC_BUF_SIZE 1024
char procfs_buf[PROC_BUF_SIZE];
size_t procfs_buf_size = 0;

DEFINE_HASHTABLE(pid_hashtable, 8);

struct pid_hashtable_entry
{
    pid_t pid;
    struct hlist_node node;
};

static void pid_hashtable_reset(void)
{
    struct pid_hashtable_entry *entry;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(pid_hashtable, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
}

static int pid_hashtable_add(pid_t pid)
{
    struct pid_hashtable_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        pr_err("kmalloc() failed");
        return -ENOMEM;
    }

    entry->pid = pid;
    hash_add(pid_hashtable, &entry->node, pid);

    return 0;
}

static struct pid_hashtable_entry *pid_hashtable_find(pid_t pid)
{
    struct pid_hashtable_entry *entry;

    hash_for_each_possible(pid_hashtable, entry, node, pid) {
        if (entry->pid == pid) {
            return entry;
        }
    }

    return NULL;
}

/*
 * Must be called under rcu_read_lock().
 */
struct task_struct *find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
			 "find_task_by_pid_ns() needs rcu_read_lock() protection");
	return pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
}

struct task_struct *find_task_by_vpid(pid_t vnr)
{
	return find_task_by_pid_ns(vnr, task_active_pid_ns(current));
}

struct task_struct *find_get_task_by_vpid(pid_t nr)
{
	struct task_struct *task;

	rcu_read_lock();
	task = find_task_by_vpid(nr);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	return task;
}

static int enable_polling_for_pid(pid_t pid)
{
    /* TODO: collisions can happen if there are equal PIDs
     * in different namespaces */

    /* TODO: check if already enabled? */

    int ret;
    struct task_struct *task = find_get_task_by_vpid(pid);

    if (!task) {
        pr_err("Failed to enable polling for pid %i: task_struct not found\n", pid);
        return -ESRCH;
    }

    ret = pid_hashtable_add(pid);
    if (ret != 0) {
        pr_err("Failed to enable polling for pid %i\n", pid);
        goto put_task_struct;
    }

    pr_info("Enabled polling for pid %i [%s]\n", pid, task->comm);

put_task_struct:
    put_task_struct(task);
    return ret;
}

static int parse_config(const char *buf, size_t count)
{
    pid_hashtable_reset();

    const char *ptr = buf;
    int ret;
    size_t processed = 0;

    while (processed < count) {
        if (*ptr == ' ' || *ptr == '\n') {
            ptr++;
            processed++;
            continue;
        }

        // TODO: kstrtoint handles only null-terminated strings,
        // need to set null byte in string to parse multiple pids
        pid_t pid;
        ret = kstrtoint(ptr, 10, &pid);
        if (ret) {
            pr_err("Failed to parse pid at position %ld\n", ptr - buf);
            return ret;
        }

        ret = enable_polling_for_pid(pid);
        if (ret != 0) {
            return ret;
        }

        while (processed < count && *ptr != ' ' && *ptr != '\n') {
            ptr++;
            processed++;
        }
    }

    return 0;
}

static void log_buffer(char *buf, size_t len)
{
    print_hex_dump(KERN_INFO, "Polled pids: ", DUMP_PREFIX_NONE, 16, 1,
                   buf, len, true);
}

static ssize_t polled_pids_read(struct file *file, char __user *to,
                                size_t count, loff_t *ppos)
{
    ssize_t ret;

    ret = simple_read_from_buffer(to, count, ppos, procfs_buf, procfs_buf_size);
    log_buffer(procfs_buf, procfs_buf_size);

    return ret;
}

static ssize_t polled_pids_write(struct file *file, const char __user *from,
                                 size_t count, loff_t *ppos)
{
    ssize_t ret;

    loff_t start = 0; /* ignore ppos and always write from the beginning of buffer */
    ssize_t written = simple_write_to_buffer(procfs_buf, PROC_BUF_SIZE, &start, from, count);
    if (written != count) {
        pr_err("Failed to write data to procfs buffer (maybe buffer is too small)\n");
        goto error;
    }

    ret = parse_config(procfs_buf, written);
    if (ret > 0)
        procfs_buf_size = written;
    else
        goto error;

    return written;

error:
    procfs_buf_size = 0;
    return -EINVAL;
}


static const struct proc_ops polled_pids_ops = {
	.proc_read	= polled_pids_read,
	.proc_write	= polled_pids_write,
};

static bool task_is_polled(pid_t pid)
{
    return pid_hashtable_find(pid) ? true : false;
}

/* A pointer to original function. Is initialized inside fh_install_hook. */
static asmlinkage void (*real_submit_bio)(struct bio *bio);

static asmlinkage void fh_submit_bio(struct bio *bio)
{
    if (!task_is_polled(current->pid)) {
        return real_submit_bio(bio);
    }

    /* check if submit_bio is called from ext4_mpage_readpages */

    /* TODO: this can be optimized by remembering
     * ext4_mpage_readpages() addreses beforehand */
    char symname[KSYM_NAME_LEN];
    void *ret = __builtin_return_address(0);
    __lookup_symbol_name((unsigned long) ret, symname);

    if (strcmp(symname, "ext4_mpage_readpages") != 0)
        return real_submit_bio(bio);

    bio->bi_opf |= REQ_POLLED;

    real_submit_bio(bio);

    for (;;) {
        set_current_state(TASK_UNINTERRUPTIBLE);

        if (bio_poll(bio, NULL, 0) > 0)
            break;

        blk_io_schedule();
    }
    __set_current_state(TASK_RUNNING);
    bio_clear_polled(bio);
}


struct ftrace_hook submit_bio_hook =
    HOOK("submit_bio", fh_submit_bio, &real_submit_bio);

static int __init use_polling_init(void)
{
    pr_info("Loading use-polling module...\n");

    lookup_kallsyms_lookup_name();
    lookup_lookup_symbol_name();

    proc_create("polled_pids", 0, NULL, &polled_pids_ops);

	fh_install_hook(&submit_bio_hook);

	return 0;
}

static void __exit use_polling_exit(void)
{
	if (fh_installed(&submit_bio_hook))
	    fh_remove_hook(&submit_bio_hook);

	pr_info("Unloading use-polling module...\n");
}

module_init(use_polling_init);
module_exit(use_polling_exit);
