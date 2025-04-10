#ifndef CONFIG_H
#define CONFIG_H

#include <linux/printk.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#define PROCFS_NAME "force_iopoll_config"
#define MAX_PROC_SIZE 4096

extern DECLARE_HASHTABLE(config_hashtable, 8);

struct pid_config {
    int pid;
    unsigned long flags;
    struct hlist_node node;
};

enum flag_bits {
    __FLAG_CLONE_INHERIT = 0,
    __FLAG_NR_BITS
};

#define FLAG_CLONE_INHERIT (1UL << __FLAG_CLONE_INHERIT)

int config_init(void);
void config_exit(void);

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
    struct pid_config *entry = config_hashtable_find(pid);
    if (entry) {
        entry->flags = flags;
    }
    else {
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            pr_err("failed to allocate memory for PID entry\n");
            return;
        }
        entry->pid = pid;
        entry->flags = flags;
        hash_add(config_hashtable, &entry->node, pid);
    }
}

static inline void config_hashtable_clear(void)
{
    struct pid_config *entry;
    struct hlist_node *tmp;
    int i;

    hash_for_each_safe(config_hashtable, i, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
}

static inline bool config_iopoll_enabled(pid_t pid)
{
    /* poll pid if it is present in config */
    return config_hashtable_find(pid);
}

static inline unsigned long config_pid_flags(pid_t pid)
{
    struct pid_config *entry;
    entry = config_hashtable_find(pid);

    return entry ? entry->flags : 0;
}
#endif // !CONFIG_H
