/*
 * Intercept functions in Linux kernel with FTrace
 * https://habr.com/ru/articles/413241/
 * */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ftrace_hook.h"

#include <linux/ftrace.h>
#include <linux/kallsyms.h>

static void notrace ftrace_hook_thunk(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE)) {
        ftrace_regs_set_instruction_pointer(fregs, (unsigned long)hook->func);
    }
}

int ftrace_hook_install(struct ftrace_hook *hook, void *orig_func, void *func)
{
    int err;

    if (!orig_func || !func) {
        return -EINVAL;
    }

    hook->orig_func = orig_func;
    hook->func = func;
    hook->ops.func = ftrace_hook_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, (unsigned long)hook->orig_func, 0, 0);
    if (err) {
        pr_err("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("register_ftrace_function() failed: %d\n", err);

        /* Don't forget to remove ip in case of error */
        ftrace_set_filter_ip(&hook->ops, (unsigned long)hook->orig_func, 1, 0);

        return err;
    }

    hook->installed = true;

    char orig_sym[KSYM_NAME_LEN];
    sprint_symbol(orig_sym, (unsigned long)hook->orig_func);

    char sym[KSYM_NAME_LEN];
    sprint_symbol(sym, (unsigned long)hook->func);

    pr_info("installed ftrace hook: %s --> %s\n", orig_sym, sym);
    return 0;
}

int ftrace_hook_remove(struct ftrace_hook *hook)
{
    int err;

    if (!ftrace_hook_is_installed(hook)) {
        return 0;
    }

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        pr_info("unregister_ftrace_function() failed: %d\n", err);
        return err;
    }

    err = ftrace_set_filter_ip(&hook->ops, (unsigned long)hook->orig_func, 1, 0);
    if (err) {
        pr_info("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    hook->installed = false;

    char orig_sym[KSYM_NAME_LEN];
    sprint_symbol(orig_sym, (unsigned long)hook->orig_func);

    pr_info("removed ftrace hook at: %s\n", orig_sym);
    return 0;
}
