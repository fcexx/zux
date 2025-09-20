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

all: $(BINDIR)/solarImg solar.iso

$(BINDIR)/solarImg: $(OBJECTS)
	@mkdir -p $(dir $@)
	@echo Linking...
	@$(LD) -n -o $@ -T linker.ld $(OBJECTS)

hda/boot/solarImg: $(BINDIR)/solarImg
	@mkdir -p $(dir $@)
	@cp $< $@

solar.iso: hda/boot/solarImg hda/boot/grub/grub.cfg
	@echo "Creating bootable ISO: $@"
	@mkdir -p $(BUILDDIR)/isodir/boot/grub
	@cp hda/boot/solarImg $(BUILDDIR)/isodir/boot/solarImg
	@-cp hda/boot/bzbx $(BUILDDIR)/isodir/boot/bzbx
	@cp hda/boot/grub/grub.cfg $(BUILDDIR)/isodir/boot/grub/grub.cfg
	@grub-mkrescue -o $@ $(BUILDDIR)/isodir

$(OBJDIR)/%.o: $(SRCDIR)/%.asm
	@mkdir -p $(dir $@)
	@echo "NASM		$<"
	@$(AS) -f elf64 $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.S
	@mkdir -p $(dir $@)
	@echo "GAS		$<"
	@$(GAS) --64 $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "CPP		$<"
	@$(CC) -c $< -o $@ -std=c++17 -ffreestanding -fno-exceptions -fno-rtti -Wall -Wextra -g -Iinclude -w

$(OBJDIR)/%.o: libc/%.cpp
	@mkdir -p $(dir $@)
	@echo "CPP		$<"
	@$(CC) -c $< -o $@ -std=c++17 -ffreestanding -fno-exceptions -fno-rtti -Wall -Wextra -g -Iinclude -w

clean:
	sudo rm -rf $(BUILDDIR) solar.iso

run:
	@qemu-system-x86_64 -cdrom solar.iso -m 512M -debugcon stdio

debug:
	qemu-system-x86_64 -cdrom solar.iso -m 512M -s -S -debugcon stdio

vmdk:
	@echo "Not supported for ISO build"