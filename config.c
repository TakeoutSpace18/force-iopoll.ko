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

DEFINE_HASHTABLE(config_hashtable, 8);
DEFINE_RWLOCK(config_hashtable_lock);

static struct proc_dir_entry *proc_file;

int config_enable_iopoll(pid_t pid, unsigned long flags)
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
    pr_info("enabled polling for pid %i (clone_inherit=%s) [%s]\n", pid, 
            flags & FLAG_CLONE_INHERIT ? "yes" : "no", task->comm);

    put_task_struct(task);
    return 0;
}

int config_disable_iopoll(pid_t pid)
{
    config_hashtable_remove(pid);
    return 0;
}

static unsigned long parse_flags(char *flags_str)
{
    static const match_table_t flag_tokens = {
        {FLAG_CLONE_INHERIT, "clone_inherit"},
        {-1, NULL}
    };

    unsigned long flags = 0;
    substring_t args[MAX_OPT_ARGS];
    char *p, *s;
    int token;

    if (!flags_str)
        return 0;

    s = flags_str;
    while ((p = strsep(&s, ",")) != NULL) {
        if (!*p)
            continue;
        
        token = match_token(p, flag_tokens, args);
        if (token < 0)
            continue;
        
        flags |= token;
    }

    return flags;
}

static void parse_config_line(char *line)
{
    pid_t pid;
    unsigned long flags = 0;
    char *pid_str, *flags_str = NULL;

    /* Trim leading whitespace */
    while (*line && (*line == ' ' || *line == '\t'))
        line++;

    /* Skip empty lines and comments */
    if (*line == '\0' || *line == '#')
        return;

    /* Find the PID part */
    pid_str = strsep(&line, " \t");
    if (!pid_str || kstrtoint(pid_str, 10, &pid) < 0)
        return;

    /* Check if flags are present */
    if (line && *line) {
        /* Skip whitespace */
        while (*line && (*line == ' ' || *line == '\t'))
            line++;

        if (!strncmp(line, "flags=", 6)) {
            line += 6;  /* Skip "flags=" */
            flags_str = line;
        }
    }

    if (flags_str)
        flags = parse_flags(flags_str);

    config_enable_iopoll(pid, flags);
}

static void parse_config(char *buffer, size_t count)
{
    char *line, *next_line;
    
    config_hashtable_clear();
    
    line = buffer;
    while (line) {
        /* Find the end of the current line */
        next_line = strchr(line, '\n');
        if (next_line) {
            *next_line = '\0';
            next_line++;
        }
        
        parse_config_line(line);
        line = next_line;
    }
}

static const char *flag_names[] = {
    "clone_inherit"
};

static int proc_show(struct seq_file *f, void *v)
{
    struct pid_config *entry;
    int i;

    seq_printf(f, "# %s configuration\n", KBUILD_MODNAME);
    seq_puts(f, "# Format: <pid> [flags=flag1,flag2,...]\n\n");
    seq_puts(f, "# Flags:\n");
    seq_puts(f, "# \tclone_inherit - poll children of process with iopoll enabled\n");
    seq_puts(f, "\n");

    hash_for_each(config_hashtable, i, entry, node) {
        seq_printf(f, "%d", entry->pid);
        
        if (entry->flags) {
            seq_puts(f, " flags=");
            
            /* First flag doesn't need a comma */
            bool first = true;
            int j;
            
            for (j = 0; j < __FLAG_NR_BITS; j++) {
                if (entry->flags & (1UL << j)) {
                    if (!first)
                        seq_puts(f, ",");
                    seq_puts(f, flag_names[j]);
                    first = false;
                }
            }
        }
        
        seq_puts(f, "\n");
    }

    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static ssize_t proc_write(struct file *file, const char __user *buffer,
                          size_t count, loff_t *pos)
{
    char *kbuf;

    if (count > MAX_PROC_SIZE)
        count = MAX_PROC_SIZE;

    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buffer, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kbuf[count] = '\0';
    parse_config(kbuf, count);
    kfree(kbuf);

    return count;
}

static const struct proc_ops config_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_write = proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

int config_init(void)
{
    hash_init(config_hashtable);
    rwlock_init(&config_hashtable_lock);
    
    proc_file = proc_create(PROCFS_NAME, 0644, NULL, &config_fops);
    if (!proc_file) {
        pr_err("failed to create proc entry\n");
        return -ENOMEM;
    }
    
    pr_info("created /proc/%s\n", PROCFS_NAME);
    return 0;
}

void config_exit(void)
{
    proc_remove(proc_file);
    pr_info("removed /proc/%s\n", PROCFS_NAME);

    config_hashtable_clear();
}
