#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>

#include <linux/force_iopoll.h>

#define DEFAULT_DEVICE_PATH "/dev/force_iopoll"
#define MAX_DEVICE_PATH 512

// clang-format off
static struct option long_options[] = {
    {"follow-forks", no_argument,       0, 'f'},
    {"hybrid",       no_argument,       0, 'y'},
    {"device",       required_argument, 0, 'd'},
    {"help",         no_argument,       0, 'h'},
    {0, 0, 0, 0}
};
// clang-format on

static void print_usage(const char *prog)
{
    // clang-format off
    fprintf(stderr, "Usage: %s add <pid> [OPTIONS]\n", prog);
    fprintf(stderr, "       %s remove <pid> [OPTIONS]\n", prog);
    fprintf(stderr, "       %s enable-global [OPTIONS]\n", prog);
    fprintf(stderr, "       %s disable-global [OPTIONS]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  add <pid>             enable iopoll for process\n");
    fprintf(stderr, "  remove <pid>          disable iopoll for process\n");
    fprintf(stderr, "  enable-global         enable iopoll for all processes in system\n");
    fprintf(stderr, "  disable-global        disable global iopoll\n\n");
    fprintf(stderr, "Options (for 'add' command):\n");
    fprintf(stderr, "  -f, --follow-forks    iopoll will be inherited by forked processes\n");
    fprintf(stderr, "  -y, --hybrid          sleep before polling to reduce CPU usage\n\n");
    fprintf(stderr, "Options (for 'enable-global' command):\n");
    fprintf(stderr, "  -y, --hybrid          sleep before polling to reduce CPU usage\n\n");
    fprintf(stderr, "Options (for all commands):\n");
    fprintf(stderr, "  -d, --device PATH     use custom device path (default: %s)\n", DEFAULT_DEVICE_PATH);
    fprintf(stderr, "  -h, --help            show this help message\n");
    // clang-format on
}

static int add_process(int fd, pid_t pid, int flags)
{
    struct force_iopoll_addprocess_params params = {
        .pid = pid,
        .flags = flags
    };
    
    if (ioctl(fd, FORCE_IOPOLL_IOCTL_ADDPROCESS, &params) < 0) {
        perror("ioctl FORCE_IOPOLL_IOCTL_ADDPROCESS");
        return -1;
    }
    
    printf("Enabled iopoll for PID=%i\n", pid);
    if (flags & FORCE_IOPOLL_FLAG_FOLLOW_FORKS) {
        printf("  - follow-forks enabled\n");
    }
    if (flags & FORCE_IOPOLL_FLAG_HYBRID) {
        printf("  - hybrid mode enabled\n");
    }
    
    return 0;
}

static int remove_process(int fd, pid_t pid)
{
    struct force_iopoll_removeprocess_params params = {
        .pid = pid
    };
    
    if (ioctl(fd, FORCE_IOPOLL_IOCTL_REMOVEPROCESS, &params) < 0) {
        perror("ioctl FORCE_IOPOLL_IOCTL_REMOVEPROCESS");
        return -1;

    }
    printf("Disabled forced iopoll for PID=%i\n", pid);
    return 0;
}

static int enable_global(int fd, int flags)
{
    struct force_iopoll_enableglobal_params params = {
        .flags = flags
    };
    
    if (ioctl(fd, FORCE_IOPOLL_IOCTL_ENABLEGLOBAL, &params) < 0) {
        perror("ioctl FORCE_IOPOLL_IOCTL_ENABLEGLOBAL");
        return -1;
    }
    
    printf("Enabled global iopoll\n");
    if (flags & FORCE_IOPOLL_FLAG_HYBRID) {
        printf("  - hybrid mode enabled\n");
    }
    
    return 0;
}

static int disable_global(int fd)
{
    if (ioctl(fd, FORCE_IOPOLL_IOCTL_DISABLEGLOBAL) < 0) {
        perror("ioctl FORCE_IOPOLL_IOCTL_DISABLEGLOBAL");
        return -1;
    }
    
    printf("Disabled global iopoll\n");
    return 0;
}

#define CHECK_INVALID_FLAG(flag, flag_human, valid_cmds) \
    if (flags & FORCE_IOPOLL_FLAG_##flag) { \
        fprintf(stderr, "Error: Flag " flag_human " is only valid for " valid_cmds "\n"); \
        goto cleanup; \
    }

int main(int argc, char *argv[])
{
    int fd;
    int ret = 1;
    int flags = 0;
    int opt;
    int option_index = 0;

    char device_path[MAX_DEVICE_PATH + 1];
    strncpy(device_path, DEFAULT_DEVICE_PATH, MAX_DEVICE_PATH);
    
    while ((opt = getopt_long(argc, argv, "fyd:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'f':
                flags |= FORCE_IOPOLL_FLAG_FOLLOW_FORKS;
                break;
            case 'y':
                flags |= FORCE_IOPOLL_FLAG_HYBRID;
                break;
            case 'd':
                strncpy(device_path, optarg, MAX_DEVICE_PATH);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* check for command and PID arguments */
    if (optind >= argc) {
        fprintf(stderr, "Error: Missing command\n");
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[optind];

    pid_t pid = -1;
    bool pid_required = strcmp(command, "add") == 0 || strcmp(command, "remove") == 0;
    
    if (pid_required) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: Missing PID argument\n");
            print_usage(argv[0]);
            return 1;
        }
        
        pid = atoi(argv[optind + 1]);
        if (pid <= 0) {
            fprintf(stderr, "Error: Invalid PID '%s'\n", argv[optind + 1]);
            return 1;
        }
    }
    
    /* open device */
    fd = open(device_path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Error: Cannot open device '%s': %s\n", device_path, strerror(errno));
        fprintf(stderr, "Make sure the force_iopoll kernel module is loaded\n");
        return 1;
    }
    
    /* execute command */
    if (strcmp(command, "add") == 0) {
        ret = add_process(fd, pid, flags);
    }
    else if (strcmp(command, "remove") == 0) {
        CHECK_INVALID_FLAG(FOLLOW_FORKS, "--follow-forks", "add")
        CHECK_INVALID_FLAG(HYBRID, "--hybrid", "add, enable-global")

        ret = remove_process(fd, pid);
    }
    else if (strcmp(command, "enable-global") == 0) {
        CHECK_INVALID_FLAG(FOLLOW_FORKS, "--follow-forks", "add")
        ret = enable_global(fd, flags);
    }
    else if (strcmp(command, "disable-global") == 0) {
        CHECK_INVALID_FLAG(FOLLOW_FORKS, "--follow-forks", "add")
        CHECK_INVALID_FLAG(HYBRID, "--hybrid", "add, enable-global")
        ret = disable_global(fd);
    }
    else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        goto cleanup;
    }
    
cleanup:
    close(fd);
    return ret;
}
