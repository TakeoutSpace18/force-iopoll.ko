/*
 * Intercept functions in Linux kernel with FTrace
 * https://habr.com/ru/articles/413241/
 * */
#ifndef FTRACE_HOOK_H
#define FTRACE_HOOK_H

#include <linux/ftrace.h>

/**
 * struct ftrace_hook - describes intercepted function
 *
 * @name:       name of intercepted function
 *
 * @function:   address of a function which will be called
 *              instead of original
 *
 * @original:   a pointer to a place where to write intercepted
 *              function address (is determined at hook installation)
 *
 * @address:    intercepted function address (is determined at hook installation)
 *
 * @ops:        ftrace internal data, is initialized with zeros
 *  
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;

	bool installed;
};

#define HOOK(_name, _function, _original) \
	{                                     \
		.name = (_name),                  \
		.function = (_function),          \
		.original = (_original),          \
	}

int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);

static inline bool fh_installed(struct ftrace_hook *hook)
{
	return hook->installed;
}

#endif /* !FTRACE_HOOK_H */
