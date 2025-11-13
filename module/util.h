#ifndef UTIL_H
#define UTIL_H

#include <linux/blk_types.h>
#include <linux/tracepoint.h>

/* Some kernel tracepoints are not exported to modules.
 * This function iterates over all tracepoints and finds desired by name. */
struct tracepoint *find_tracepoint(const char *tracepoint_name);

/* A hack to get address of non-exported function in kernel */
unsigned long kprobe_lookup(const char *symbol_name);

void __maybe_unused print_bio_bi_opf(blk_opf_t bi_opf);

#endif /* !UTIL_H */
