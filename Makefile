obj-m += force-iopoll.o
force-iopoll-objs := main.o ftrace-hook.o util.o config.o

KERNEL=`uname -r`

all: module

module:
	make -C /lib/modules/$(KERNEL)/build M=$(PWD) modules

install:
	cp force-iopoll.ko /lib/modules/$(KERNEL)
	depmod -a

clean:
	make -C /lib/modules/$(KERNEL)/build M=$(PWD) clean
