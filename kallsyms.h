#ifndef KALLSYMS_H
#define KALLSYMS_H

extern long unsigned int (*__kallsyms_lookup_name)(const char *name);
extern int (*__lookup_symbol_name)(unsigned long addr, char *symname);

void lookup_kallsyms_lookup_name(void);
void lookup_lookup_symbol_name(void);

#endif // !KALLSYMS_H
