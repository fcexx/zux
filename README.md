**Zux**: the first POSIX-compatible kernel developed in Russia using C, C++, and NASM assembly language. Zux kernel has the capability to implement dual boot functionality for BIOS and UEFI mode, allowing it to be run on many platforms.
To load the Zux kernel from the GRUB, the multiboot2 specification is used with an additional bzbx module. Here is a GRUB usage example:

```
multiboot2 /boot/zuxImg
module2 /boot/bzbx bzbx
boot
```


Currently, the Zux kernel supports amd64 architecture, but it will provide support for other hardware architecture in the future.

*For more information and to reach developers contact the Telegram channel: https://t.me/waruxx.*
