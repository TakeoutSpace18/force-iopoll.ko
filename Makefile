all: modules force_iopoll_ctl eval

KDIR ?= /lib/modules/`uname -r`/build

obj-y := module/
kbuild = -C $(KDIR) M=$$PWD $@

modules:
	$(Q)$(MAKE) $(kbuild)

.PHONY: force_iopoll_ctl
force_iopoll_ctl:
	make -C force_iopoll_ctl/

clean:
	$(Q)$(MAKE) $(kbuild)
	$(RM) modules.order
	make -C module/ clean
	make -C force_iopoll_ctl/ clean

install:
	make -C module/ install
	make -C force_iopoll_ctl/ install
