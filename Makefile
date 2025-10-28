ARCH = x86_64
TARGET = $(ARCH)-elf
HOST = $(ARCH)-pc-linux-gnu

CC = x86_64-elf-g++
AS = nasm
GAS = $(TARGET)-as
LD = $(TARGET)-ld

# Read .config and export all KEY=y as -DKEY for C/C++/C and -DKEY=1 for NASM
# Lines in .config must be like: KEY=y or KEY=n
DEFS := $(shell awk -F= '/^[A-Z0-9_]+=y/ { printf("-D%s ", $$1) }' .config 2>/dev/null)
NASM_DEFS := $(shell awk -F= '/^[A-Z0-9_]+=y/ { printf("-D%s=1 ", $$1) }' .config 2>/dev/null)

SRCDIR = src
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin

ASM_SOURCES = $(wildcard $(SRCDIR)/*.asm) $(wildcard $(SRCDIR)/*/*.asm)
GAS_SOURCES = $(wildcard $(SRCDIR)/*.S) $(wildcard $(SRCDIR)/*/*.S) $(wildcard $(SRCDIR)/*/*/*.S)
C_SOURCES = $(wildcard $(SRCDIR)/*.cpp) $(wildcard $(SRCDIR)/*/*.cpp) $(wildcard $(SRCDIR)/*/*/*.cpp) $(wildcard $(SRCDIR)/*/*/*/*.cpp)
CC_SOURCES = $(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/*/*.c) $(wildcard $(SRCDIR)/*/*/*.c) $(wildcard $(SRCDIR)/*/*/*/*.c)
LIBC_SOURCES = $(wildcard libc/*.cpp)

ASM_OBJECTS = $(patsubst $(SRCDIR)/%.asm, $(OBJDIR)/%.o, $(ASM_SOURCES))
GAS_OBJECTS = $(patsubst $(SRCDIR)/%.S, $(OBJDIR)/%.o, $(GAS_SOURCES))
C_OBJECTS = $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(C_SOURCES))
CC_OBJECTS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(CC_SOURCES))
LIBC_OBJECTS = $(patsubst libc/%.cpp, $(OBJDIR)/%.o, $(LIBC_SOURCES))

OBJECTS = $(ASM_OBJECTS) $(GAS_OBJECTS) $(C_OBJECTS) $(CC_OBJECTS) $(LIBC_OBJECTS)


.PHONY: all clean run

all: $(BINDIR)/zuxImg zux.iso

$(BINDIR)/zuxImg: $(OBJECTS)
	@mkdir -p $(dir $@)
	@echo Linking...
	@$(LD) -n -o $@ -T linker.ld --allow-multiple-definition $(OBJECTS)

iso/boot/zuxImg: $(BINDIR)/zuxImg
	@mkdir -p $(dir $@)
	@cp $< $@

zux.iso: iso/boot/zuxImg iso/boot/grub/grub.cfg
	@echo !!KERNEL DONE!!: zuxImg
	@echo "Creating bootable ISO: $@"
	@mkdir -p $(BUILDDIR)/isodir/boot/grub
	@cp iso/boot/zuxImg $(BUILDDIR)/isodir/boot/zuxImg
	@-cp iso/boot/bzbx $(BUILDDIR)/isodir/boot/bzbx
	@cp iso/boot/grub/grub.cfg $(BUILDDIR)/isodir/boot/grub/grub.cfg
	@grub-mkrescue -o $@ $(BUILDDIR)/isodir

$(OBJDIR)/%.o: $(SRCDIR)/%.asm
	@mkdir -p $(dir $@)
	@echo "NASM		$< $(NASM_DEFS)"
	@$(AS) $(NASM_DEFS) -f elf64 $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.S
	@mkdir -p $(dir $@)
	@echo "GAS		$<"
	@$(GAS) --64 $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "CPP		$< $(DEFS)"
	@$(CC) -c $< -o $@ -std=c++17 -ffreestanding -fno-exceptions -fno-rtti -Wall -Wextra -g -Iinclude -w $(DEFS)

$(OBJDIR)/%.o: libc/%.cpp
	@mkdir -p $(dir $@)
	@echo "CPP		$< $(DEFS)"
	@$(CC) -c $< -o $@ -std=c++17 -ffreestanding -fno-exceptions -fno-rtti -Wall -Wextra -g -Iinclude -w $(DEFS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "CC 		$<"
	@x86_64-elf-gcc -c $< -o $@ -std=gnu11 -ffreestanding -Wall -Wextra -g -Iinclude -w $(DEFS)

clean:
	sudo rm -rf $(BUILDDIR) zux.iso

run:
	@qemu-system-x86_64 -cdrom zux.iso -m 1024M -debugcon stdio -iso ../iso.img -boot d -vga cirrus
run-uefi:
	@qemu-system-x86_64 -cdrom zux.iso -m 1200M -debugcon stdio -iso ../iso.img -boot d -vga virtio -bios /usr/share/OVMF/OVMF_CODE.fd

debug:
	qemu-system-x86_64 -cdrom zux.iso -m 512M -s -S -debugcon stdio &
	QEMU_PID=$!
	sleep 2
	gdb -x debug.gdb
	kill $QEMU_PID 

kernel: $(BINDIR)/zuxImg
	@echo "kernel done: " $<
	@cp $< ./zuxImg

vmdk:
	@echo "Not supported for ISO build"