#ifndef CONFIG_H
#define CONFIG_H

#include <linux/printk.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#define PROCFS_NAME "force_iopoll_config"
#define MAX_PROC_SIZE 4096

extern DECLARE_HASHTABLE(config_hashtable, 8);
extern rwlock_t config_hashtable_lock;

struct pid_config {
    int pid;
    unsigned long flags;
    struct hlist_node node;
};

enum flag_bits {
    __FLAG_FOLLOW_FORKS = 0,
    __FLAG_NR_BITS
};

#define FLAG_FOLLOW_FORKS (1UL << __FLAG_FOLLOW_FORKS)

int config_init(void);
void config_exit(void);

int config_enable_iopoll(pid_t pid, unsigned long flags);
int config_disable_iopoll(pid_t pid);

static inline struct pid_config *config_hashtable_find(pid_t pid)
{
    struct pid_config *entry;

    hash_for_each_possible(config_hashtable, entry, node, pid) {
        if (entry->pid == pid) {
            return entry;
        }
    }

    return NULL;
}

static inline void config_hashtable_add_or_update(pid_t pid, unsigned long flags)
{
    write_lock(&config_hashtable_lock);
    struct pid_config *entry = config_hashtable_find(pid);

    if (entry) {
        entry->flags = flags;
    }
    else {
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            pr_err("failed to allocate memory for PID entry\n");
            write_unlock(&config_hashtable_lock);
            return;
        }
        entry->pid = pid;
        entry->flags = flags;
        hash_add(config_hashtable, &entry->node, pid);
    }

    write_unlock(&config_hashtable_lock);
}

static inline void config_hashtable_clear(void)
{
    struct pid_config *entry;
    struct hlist_node *tmp;
    int i;

    write_lock(&config_hashtable_lock);

    hash_for_each_safe(config_hashtable, i, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }

    write_unlock(&config_hashtable_lock);
}

static inline void config_hashtable_remove(pid_t pid)
{
    struct pid_config *entry;
    struct hlist_node *tmp;

    write_lock(&config_hashtable_lock);

    hash_for_each_possible_safe(config_hashtable, entry, tmp, node, pid) {
        if (entry->pid == pid) {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }
    }

    write_unlock(&config_hashtable_lock);
}

static inline bool config_iopoll_enabled(pid_t pid, unsigned long *flags)
{
    struct pid_config *entry;

    read_lock(&config_hashtable_lock);
    entry = config_hashtable_find(pid);

    if (entry) {
        if (flags)
            *flags = entry->flags;
        read_unlock(&config_hashtable_lock);
        return true;
    }

    read_unlock(&config_hashtable_lock);
    return false;
}

#endif // !CONFIG_H
