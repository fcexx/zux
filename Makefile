ARCH = x86_64
TARGET = $(ARCH)-elf
HOST = $(ARCH)-pc-linux-gnu

CC = x86_64-elf-g++
AS = nasm
GAS = $(TARGET)-as
LD = $(TARGET)-ld

SRCDIR = src
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin

ASM_SOURCES = $(wildcard $(SRCDIR)/*.asm) $(wildcard $(SRCDIR)/*/*.asm)
GAS_SOURCES = $(wildcard $(SRCDIR)/*.S) $(wildcard $(SRCDIR)/*/*.S) $(wildcard $(SRCDIR)/*/*/*.S)
C_SOURCES = $(wildcard $(SRCDIR)/*.cpp) $(wildcard $(SRCDIR)/*/*.cpp) $(wildcard $(SRCDIR)/*/*/*.cpp)
LIBC_SOURCES = $(wildcard libc/*.cpp)

ASM_OBJECTS = $(patsubst $(SRCDIR)/%.asm, $(OBJDIR)/%.o, $(ASM_SOURCES))
GAS_OBJECTS = $(patsubst $(SRCDIR)/%.S, $(OBJDIR)/%.o, $(GAS_SOURCES))
C_OBJECTS = $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(C_SOURCES))
LIBC_OBJECTS = $(patsubst libc/%.cpp, $(OBJDIR)/%.o, $(LIBC_SOURCES))

OBJECTS = $(ASM_OBJECTS) $(GAS_OBJECTS) $(C_OBJECTS) $(LIBC_OBJECTS)


.PHONY: all clean run

all: $(BINDIR)/solarImg solar.img

$(BINDIR)/solarImg: $(OBJECTS)
	@mkdir -p $(dir $@)
	$(LD) -n -o $@ -T linker.ld $(OBJECTS)

hda/boot/solarImg: $(BINDIR)/solarImg
	@mkdir -p $(dir $@)
	cp $< $@

solar.img: hda/boot/solarImg hda/boot/grub/grub.cfg
	@echo "Creating bootable FAT32 image: $@"
	sh -c 'set -e; \
		rm -rf $(BUILDDIR)/mnt_tmp; \
		LOOP_DEVICE=$$(sudo losetup -j $@ | awk "{print \$$1}" | tr -d ":"); \
		if [ -n "$$LOOP_DEVICE" ]; then \
			sudo umount $${LOOP_DEVICE}p1 2>/dev/null || true; \
			sudo losetup -d $$LOOP_DEVICE 2>/dev/null || true; \
		fi; \
		sudo dd if=/dev/zero of=$@ bs=1M count=64; \
		sudo parted -s $@ mklabel msdos; \
		sudo parted -s $@ mkpart primary fat32 1MiB 100%; \
		sudo parted -s $@ set 1 boot on; \
		LOOP_DEVICE=$$(sudo losetup -f --show $@); \
		sudo partprobe $$LOOP_DEVICE; \
		sleep 3; \
		PARTITION_DEVICE=$${LOOP_DEVICE}p1; \
		sudo mkfs.fat -F 32 $$PARTITION_DEVICE; \
		sudo mkdir -p $(BUILDDIR)/mnt_tmp; \
		sudo mount $$PARTITION_DEVICE $(BUILDDIR)/mnt_tmp; \
		sudo mkdir -p $(BUILDDIR)/mnt_tmp/boot/grub; \
		sudo cp -rf hda/* $(BUILDDIR)/mnt_tmp/; \
		sudo cp hda/boot/solarImg $(BUILDDIR)/mnt_tmp/boot/solarImg; \
		sudo cp hda/boot/grub/grub.cfg $(BUILDDIR)/mnt_tmp/boot/grub/grub.cfg; \
		sudo grub-install --target=i386-pc --boot-directory=$(BUILDDIR)/mnt_tmp/boot --modules="fat multiboot2 normal boot part_msdos" $$LOOP_DEVICE; \
		sudo umount $(BUILDDIR)/mnt_tmp; \
		sudo losetup -d $$LOOP_DEVICE; \
		sudo rm -rf $(BUILDDIR)/mnt_tmp; \
		sudo chown $(USER):$(USER) $@; \
	'

$(OBJDIR)/%.o: $(SRCDIR)/%.asm
	@mkdir -p $(dir $@)
	$(AS) -f elf64 $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.S
	@mkdir -p $(dir $@)
	$(GAS) --64 $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CC) -c $< -o $@ -std=c++17 -ffreestanding -fno-exceptions -fno-rtti -Wall -Wextra -g -Iinclude

$(OBJDIR)/%.o: libc/%.cpp
	@mkdir -p $(dir $@)
	$(CC) -c $< -o $@ -std=c++17 -ffreestanding -fno-exceptions -fno-rtti -Wall -Wextra -g -Iinclude

clean:
	sudo rm -rf $(BUILDDIR) solar.img

run:
	qemu-system-x86_64 -drive format=raw,file=solar.img -m 512M -debugcon stdio

debug:
	qemu-system-x86_64 -drive format=raw,file=solar.img -m 512M -s -S -debugcon stdio

vmdk:
	qemu-img convert -f raw -O vmdk solar.img solar.vmdk