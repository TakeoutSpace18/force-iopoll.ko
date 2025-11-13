#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "config.h"

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/parser.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "linux/force_iopoll.h"

DEFINE_HASHTABLE(config_hashtable, 8);
DEFINE_RWLOCK(config_lock);

bool config_iopoll_global;
module_param_named(iopoll_global, config_iopoll_global, bool, 0444);
MODULE_PARM_DESC(iopoll_global, "Enable iopoll for every process");

int config_iopoll_global_flags;
module_param_named(iopoll_global_flags, config_iopoll_global_flags, int, 0444);
MODULE_PARM_DESC(iopoll_global_flags, "Flags that will be used for global iopoll");

static struct proc_dir_entry *proc_file;

static const char *flag_names[] = {
    "follow_forks",
    "hybrid"
};

#define MAX_FLAGS_STR 512

static void flags_to_str(char *str, int flags)
{
    bool first = true;
    size_t written = 0;
    
    for (int i = 0; i < FORCE_IOPOLL_NR_FLAGS; i++) {
        if (flags & (1ULL << i)) {
            if (!first) {
                written += snprintf(str + written, MAX_FLAGS_STR - written, ",");
            }
            written += snprintf(str + written, MAX_FLAGS_STR - written, "%s", flag_names[i]);
            first = false;
        }
    }
}

int config_add_pid(pid_t pid, int flags)
{
    /* TODO: collisions can happen if there are equal PIDs
     * in different namespaces */

    struct pid *pid_struct = find_get_pid(pid);
    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);

    if (!task) {
        pr_err("failed to enable polling for pid %i: task_struct not found\n", pid);
        return -ESRCH;
    }

    config_hashtable_add_or_update(pid, flags);

    char flags_str[MAX_FLAGS_STR];
    flags_to_str(flags_str, flags);

    pr_info("enabled polling for pid %i (flags=%s) [%s]\n",
            pid,
            flags ? flags_str : "none",
            task->comm);

    put_task_struct(task);
    return 0;
}

int config_remove_pid(pid_t pid)
{
    struct pid *pid_struct = find_get_pid(pid);
    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);

    config_hashtable_remove(pid);

    pr_info("disabled polling for pid %i [%s]\n", pid, task->comm);

    put_task_struct(task);
    return 0;
}

int config_enable_global(int flags)
{
    write_lock(&config_lock);
    config_iopoll_global = true;
    config_iopoll_global_flags = flags;
    write_unlock(&config_lock);

    pr_info("global iopoll enabled");
    return 0;
}

int config_disable_global(void)
{
    write_lock(&config_lock);
    config_iopoll_global = false;
    write_unlock(&config_lock);

    pr_info("global iopoll disabled");
    return 0;
}

static int proc_show(struct seq_file *f, void *v)
{
    struct pid_config *entry;

    read_lock(&config_lock);

    int i;
    hash_for_each(config_hashtable, i, entry, node) {
        char flags_str[MAX_FLAGS_STR];
        flags_to_str(flags_str, entry->flags);

        struct pid *pid_struct = find_get_pid(entry->pid);
        struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);

        seq_printf(f, "%d flags=%s [%s]\n",
                   entry->pid,
                   entry->flags ? flags_str : "none",
                   task->comm);

        put_pid(pid_struct);
        put_task_struct(task);
    }

    read_unlock(&config_lock);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops config_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

int config_init(void)
{
    hash_init(config_hashtable);
    rwlock_init(&config_lock);
    
    proc_file = proc_create(PROCFS_NAME, 0644, NULL, &config_fops);
    if (!proc_file) {
        pr_err("failed to create proc entry\n");
        return -ENOMEM;
    }
    
    pr_info("created /proc/%s\n", PROCFS_NAME);

    if (config_global_iopoll_enabled(NULL)) {
        pr_info("global iopoll enabled");
    }
    return 0;
}

void config_exit(void)
{
    proc_remove(proc_file);
    pr_info("removed /proc/%s\n", PROCFS_NAME);

    config_hashtable_clear();
}
