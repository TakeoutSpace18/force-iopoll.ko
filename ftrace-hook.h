/*
 * https://habr.com/ru/articles/413241/
 *
 * */
#ifndef FTRACE_HOOK_H
#define FTRACE_HOOK_H

/**
 * struct ftrace_hook - описывает перехватываемую функцию
 *
 * @name:       имя перехватываемой функции
 *
 * @function:   адрес функции-обёртки, которая будет вызываться вместо
 *              перехваченной функции
 *
 * @original:   указатель на место, куда следует записать адрес
 *              перехватываемой функции, заполняется при установке
 *
 * @address:    адрес перехватываемой функции, выясняется при установке
 *
 * @ops:        служебная информация ftrace, инициализируется нулями,
 *              при установке перехвата будет доинициализирована
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;

	bool installed;
};

#define HOOK(_name, _function, _original)     \
{                                             \
    .name = (_name), .function = (_function), \
    .original = (_original),                  \
}

int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);

static inline bool fh_installed(struct ftrace_hook *hook)
{
	return hook->installed;
}

#endif /* !FTRACE_HOOK_H */
