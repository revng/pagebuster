ccflags-y := \
  -std=gnu99 \
  -Werror \
  -Wno-declaration-after-statement \
  $(CCFLAGS)

obj-m+=pagebuster.o

KBUILD_DIR=/lib/modules/$(shell uname -r)/build

# Kernel module build dependency
all:
	make -C $(KBUILD_DIR) M=$(PWD) modules
#
# Kernel module clean dependency
clean:
	make -C $(KBUILD_DIR) M=$(PWD) clean
