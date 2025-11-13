all: modules

KDIR ?= /lib/modules/`uname -r`/build

obj-m = force_iopoll.o
force_iopoll-m = main.o ftrace_hook.o util.o config.o
ccflags-y += -g 

kbuild = -C $(KDIR) M=$$PWD $@

modules:
	$(Q)$(MAKE) $(kbuild) -Ilinux

install: modules
	cp force_iopoll.ko /lib/modules/`uname -r`/
	depmod -a

clean:
	$(Q)$(MAKE) $(kbuild)

