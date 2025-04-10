/*
 * https://habr.com/ru/articles/413241/
 *
 * */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/ftrace.h>
#include <linux/kprobes.h>

#include "ftrace-hook.h"
#include "kallsyms.h"

MODULE_LICENSE("GPL");

static int resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = __kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_info("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	*((unsigned long *)hook->original) = hook->address;
	pr_info("resolved %s: %lx\n", hook->name, hook->address);

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE))
		fregs->regs.ip = (unsigned long)hook->function;
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_info("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_info("register_ftrace_function() failed: %d\n", err);

		/* Don't forget to disable ftrace in case of error */
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

		return err;
	}

	hook->installed = true;
    pr_info("installed %s hook\n", hook->name);
	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_info("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_info("ftrace_set_filter_ip() failed: %d\n", err);
	}
}
