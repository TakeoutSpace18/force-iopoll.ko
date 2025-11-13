/*
 * Intercept functions in Linux kernel with FTrace
 * https://habr.com/ru/articles/413241/
 * */
#ifndef FTRACE_HOOK_H
#define FTRACE_HOOK_H

#include <linux/ftrace.h>

struct ftrace_hook
{
    void *orig_func;
    void *func;

    struct ftrace_ops ops;

    bool installed;
};

int ftrace_hook_install(struct ftrace_hook *hook, void *orig_func, void *func);
int ftrace_hook_remove(struct ftrace_hook *hook);

static inline bool ftrace_hook_is_installed(struct ftrace_hook *hook)
{
    return hook->installed;
}

#endif /* !FTRACE_HOOK_H */
