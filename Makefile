obj-m += use-polling.o
use-polling-objs := main.o ftrace-hook.o kallsyms.o

# KERNEL=`uname -r`
KERNEL=6.8.0

all:
	make -C /lib/modules/$(KERNEL)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KERNEL)/build M=$(PWD) clean
