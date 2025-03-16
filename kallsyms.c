#include <linux/kprobes.h>

#include "kallsyms.h"

long unsigned int (*__kallsyms_lookup_name)(const char *name);
int (*__lookup_symbol_name)(unsigned long addr, char *symname);

static unsigned long kprobe_lookup(const char *symbol_name)
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

void lookup_kallsyms_lookup_name(void)
{
    __kallsyms_lookup_name = (void *) kprobe_lookup("kallsyms_lookup_name");
}

void lookup_lookup_symbol_name(void)
{
    __lookup_symbol_name = (void *) kprobe_lookup("lookup_symbol_name");
}
