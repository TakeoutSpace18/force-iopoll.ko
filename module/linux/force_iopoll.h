#ifndef FORCE_IOPOLL_H
#define FORCE_IOPOLL_H

#include <linux/types.h>
#include <asm/ioctl.h>

#define FORCE_IOPOLL_FLAG_FOLLOW_FORKS (1ULL << 0) /* forced iopoll will be inherited by forked processes */
#define FORCE_IOPOLL_FLAG_HYBRID (1ULL << 1) /* delay a bit before polling to avoid wasting too much CPU resources */

#define FORCE_IOPOLL_NR_FLAGS 2

struct force_iopoll_addprocess_params {
    pid_t pid;
    int flags;
};

struct force_iopoll_removeprocess_params {
    pid_t pid;
};

struct force_iopoll_enableglobal_params {
    int flags;
};

#define FORCE_IOPOLL_IOCTL_ADDPROCESS _IOW('k', 1, struct force_iopoll_addprocess_params)
#define FORCE_IOPOLL_IOCTL_REMOVEPROCESS _IOW('k', 2, struct force_iopoll_addprocess_params)
#define FORCE_IOPOLL_IOCTL_ENABLEGLOBAL _IOW('k', 3, struct force_iopoll_enableglobal_params)
#define FORCE_IOPOLL_IOCTL_DISABLEGLOBAL _IO('k', 4)


#endif // FORCE_IOPOLL_H
