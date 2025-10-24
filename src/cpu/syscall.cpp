#include "../../include/syscall.h"
#include <stdint.h>
#include <string.h>
// Prefer explicit relative includes to satisfy standalone linter
#include "../../include/idt.h"
#include "../../include/fs_interface.h"
#include "../../include/thread.h"
#include "../../include/ps2.h"
#include "../../include/debug.h"
#include "../../include/heap.h"
#include "../../include/paging.h"
#include "../../include/pit.h"
#include "../../include/vga.h"
#include "../../include/vbe.h"

// Глобалы, ожидаемые входом SYSCALL и отладчиком GPF
extern "C" uint64_t syscall_saved_user_rsp = 0;
extern "C" uint64_t syscall_saved_user_rcx = 0;
extern "C" uint64_t dbg_saved_rbx_in = 0;
extern "C" uint64_t dbg_saved_rbx_out = 0;
extern "C" volatile uint64_t exec_trampoline = 0;
extern "C" uint64_t exec_new_rsp = 0;
extern "C" uint64_t exec_new_rip = 0;
extern "C" uint64_t exec_child_rax = 0;

// Минимальная таблица состояний выхода процессов (для совместимости со старым кодом)
static int g_exit_code[256] = {0};
static volatile int g_stopped[256] = {0};

extern "C" { uint64_t syscall_kernel_rsp0 = 0; }
// Trampoline controls for exec/vfork path (used by syscall_entry.S)
extern "C" volatile uint64_t exec_trampoline;
extern "C" uint64_t exec_new_rsp;
extern "C" uint64_t exec_new_rip;
extern "C" uint64_t exec_child_rax;
// Needed external helpers not present in headers
extern "C" const char* vfs_readlink_target(const char* path);
extern "C" void syscall_entry();

struct SyscallFrame {
        uint64_t user_r11;
        uint64_t user_rcx;
        uint64_t user_rsp;
        uint64_t a6;
        uint64_t a5;
        uint64_t a4;
        uint64_t a3;
        uint64_t a2;
        uint64_t a1;
        uint64_t nr;
};

// --- Minimal Linux x86_64 syscall numbers needed by busybox/glibc ---
enum linux_syscall_nr : uint64_t {
    LNX_read = 0,
    LNX_write = 1,
    LNX_open = 2,
    LNX_close = 3,
    LNX_stat = 4,          // legacy; not used by modern glibc on x86_64
    LNX_fstat = 5,
    LNX_lseek = 8,
    LNX_mmap = 9,
    LNX_mprotect = 10,
    LNX_munmap = 11,
    LNX_brk = 12,
    LNX_rt_sigaction = 13,
    LNX_rt_sigprocmask = 14,
    LNX_ioctl = 16,
    LNX_pread64 = 17,
    LNX_pwrite64 = 18,
    LNX_readv = 19,
    LNX_writev = 20,
    LNX_access = 21,
    LNX_pipe = 22,
    LNX_select = 23,
    LNX_sched_yield = 24,
    LNX_mremap = 25,
    LNX_msync = 26,
    LNX_mincore = 27,
    LNX_madvise = 28,
    LNX_shmget = 29,
    LNX_getpid = 39,
    LNX_uname = 63,
    LNX_readlink = 89,
    LNX_mkdir = 83,
    LNX_rmdir = 84,
    LNX_getcwd = 79,
    LNX_chdir = 80,
    LNX_arch_prctl = 158,
    LNX_exit = 60,
    LNX_wait4 = 61,
    LNX_execve = 59,
    LNX_exit_group = 231,
    LNX_clock_gettime = 228,
    LNX_openat = 257,
    LNX_newfstatat = 262,
    LNX_readlinkat = 267,
    LNX_set_tid_address = 218,
};

// Fallback segment selectors if gdt.h is not available to linter
#ifndef KERNEL_CS
#define KERNEL_CS 0x08
#endif
#ifndef USER_CS
#define USER_CS 0x1b
#endif

// open flags (Linux)
static const int O_RDONLY_ = 0;
static const int O_WRONLY_ = 1;
static const int O_RDWR_   = 2;
static const int O_CREAT_  = 64;
static const int O_TRUNC_  = 512;
static const int O_APPEND_ = 1024;

// seek whence
static const int SEEK_SET_ = 0;
static const int SEEK_CUR_ = 1;
static const int SEEK_END_ = 2;

// ioctl: TIOCGWINSZ (unix)
static const unsigned long TIOCGWINSZ_ = 0x5413;

// arch_prctl codes
static const int ARCH_SET_FS_ = 0x1002;
static const int ARCH_GET_FS_ = 0x1003;

// Simple helpers to work with current user thread and fds
static inline thread_t* cur_user() { return thread_get_current_user(); }

static inline fs_file_t* fd_get(int fd){
    thread_t* t = cur_user();
    if (!t || fd < 0 || fd >= THREAD_MAX_FD) return nullptr;
    return t->fds[fd];
}

static int fd_alloc(fs_file_t* f){
    thread_t* t = cur_user();
    if (!t) return -1;
    for (int i = 0; i < THREAD_MAX_FD; ++i){
        if (t->fds[i] == nullptr){ t->fds[i] = f; return i; }
        }
        return -1;
}

static int fd_close(int fd){
    thread_t* t = cur_user();
    if (!t || fd < 0 || fd >= THREAD_MAX_FD) return -1;
        fs_file_t* f = t->fds[fd];
    if (!f) return -1;
        t->fds[fd] = nullptr;
        return fs_close(f);
}

// Detect our pseudo-tty by private tag set in kernel.cpp
extern "C" char g_tty_private_tag;
static inline bool fd_is_tty(fs_file_t* f){ return f && f->private_data == &g_tty_private_tag; }

// Minimal write to console
static int console_write(const char* buf, size_t count){
    // kprintf prints until first NUL; we need raw bytes including '\n'.
    // Print chunk by chunk.
    for (size_t i = 0; i < count; ++i){ kprintf("%c", buf[i]); }
    return (int)count;
}

// Keyboard read (blocking-ish)
static int console_read(char* buf, size_t count){
    size_t got = 0;
    while (got < count){
        char c = kgetc();
        if (c == 0){ thread_schedule(); continue; }
        buf[got++] = c;
        if (c == '\n') break;
    }
    return (int)got;
}

// Very small user copy helpers (same address space)
static inline const char* user_cstr(const char* up){ return up; }

// brk management
extern "C" uint64_t elf_last_brk_base; // from elf.cpp
static uint64_t g_brk_current = 0;
static uint64_t g_mmap_next = 0; // next free VA for anonymous mmaps
static inline void brk_init_if_needed(){ if (!g_brk_current) g_brk_current = elf_last_brk_base; }
static inline void mmap_base_init_if_needed(){
    if (!g_mmap_next){
        // Start mmap area a bit above the loaded image end (elf_last_brk_base),
        // keep distance to avoid overlap with PT_LOAD and future brk growth.
        uint64_t base = elf_last_brk_base;
        if (base == 0) base = 0x40000000ULL; // fallback to user window base used for ET_DYN
        base = (base + (2*1024*1024 - 1)) & ~(uint64_t)(2*1024*1024 - 1); // align to 2MB
        // Also make sure we are above the typical first PT_LOAD at load_base+0x400000 (~0x40400000)
        if (base < 0x40800000ULL) base = 0x40800000ULL; // 0x40000000 + 8MB safety gap
        g_mmap_next = base;
    }
}

static uint64_t sys_brk(uint64_t newbrk){
    brk_init_if_needed();
    PrintfQEMU("[brk] in: new=0x%llx cur=0x%llx base=0x%llx\n",
               (unsigned long long)newbrk,
               (unsigned long long)g_brk_current,
               (unsigned long long)elf_last_brk_base);
    if (newbrk == 0) {
        PrintfQEMU("[brk] query -> 0x%llx\n", (unsigned long long)g_brk_current);
        return g_brk_current;
    }
    // Compatibility path: some libcs call brk(delta) early as if it were sbrk
    if (newbrk < elf_last_brk_base) {
        uint64_t delta = newbrk;
        newbrk = g_brk_current + delta;
        PrintfQEMU("[brk] treating as increment: +0x%llx -> new=0x%llx\n",
                   (unsigned long long)delta, (unsigned long long)newbrk);
    }
    uint64_t old = g_brk_current;
    // Map pages up to newbrk
    uint64_t cur = (old + 0xFFFULL) & ~0xFFFULL;
    uint64_t lim = (newbrk + 0xFFFULL) & ~0xFFFULL;
    while (cur < lim){
        void* page = kmalloc_aligned(0x1000, 0x1000);
        if (!page) break;
        paging_map_page(cur, (uint64_t)page, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
        memset((void*)cur, 0, 0x1000);
        cur += 0x1000ULL;
    }
    g_brk_current = newbrk;
    PrintfQEMU("[brk] out: cur=0x%llx (old=0x%llx)\n",
               (unsigned long long)g_brk_current,
               (unsigned long long)old);
    return g_brk_current;
}

// mmap/munmap (anonymous only)
static uint64_t sys_mmap(uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t off){
    (void)off;
    const uint64_t MAP_FIXED     = 0x10;
    const uint64_t MAP_ANONYMOUS = 0x20;
    const uint64_t MAP_PRIVATE   = 0x02;
    // Accept anonymous mappings (fd == -1), and also treat (fd == -1) non-anon as anon for simplicity
    if ((flags & MAP_ANONYMOUS) == 0 && (int64_t)fd != -1){
        return (uint64_t)-38; // -ENOSYS for file-backed mappings (not yet)
    }
    // Normalize length
    if (length == 0) return (uint64_t)-22; // -EINVAL
    // Choose base if not MAP_FIXED or addr==0
    if ((flags & MAP_FIXED) == 0 || addr == 0){
        mmap_base_init_if_needed();
        addr = g_mmap_next;
        // Advance next pointer conservatively by requested length rounded up to 2MB
        uint64_t adv = (length + (2*1024*1024 - 1)) & ~(uint64_t)(2*1024*1024 - 1);
        if (adv == 0) adv = 2*1024*1024;
        g_mmap_next += adv;
    }
    uint64_t va = addr & ~0xFFFULL;
    uint64_t end = (addr + length + 0xFFFULL) & ~0xFFFULL;
    // Derive page flags from prot (execute ignored)
    uint64_t pflags = PAGE_PRESENT | PAGE_USER;
    if (prot & 0x2) pflags |= PAGE_WRITABLE; // PROT_WRITE
    for (uint64_t v = va; v < end; v += 0x1000ULL){
        void* page = kmalloc_aligned(0x1000, 0x1000);
        if (!page) return (uint64_t)-12; // -ENOMEM
        paging_map_page(v, (uint64_t)page, pflags);
        memset((void*)v, 0, 0x1000);
    }
    PrintfQEMU("[mmap] in_addr=0x%llx len=%llu prot=0x%llx flags=0x%llx fd=%lld -> ret=0x%llx range[0x%llx..0x%llx)\n",
               (unsigned long long)(addr), (unsigned long long)length,
               (unsigned long long)prot, (unsigned long long)flags, (long long)fd,
               (unsigned long long)addr, (unsigned long long)va, (unsigned long long)end);
    return addr;
}

static uint64_t sys_munmap(uint64_t addr, uint64_t length){
    uint64_t va = addr & ~0xFFFULL;
    uint64_t end = (addr + length + 0xFFFULL) & ~0xFFFULL;
    for (uint64_t v = va; v < end; v += 0x1000ULL){ paging_unmap_page(v); }
        return 0;
}

// execve: build minimal stack and request trampoline
extern "C" uint64_t elf_last_at_phdr, elf_last_at_phent, elf_last_at_phnum, elf_last_at_entry;
extern "C" uint64_t elf_last_tls_image_vaddr, elf_last_tls_filesz, elf_last_tls_memsz, elf_last_tls_align;
extern "C" int elf64_load_process(const char* path, uint64_t user_stack_size, uint64_t* out_entry, uint64_t* out_user_stack_top);

static uint64_t sys_execve_kernel(const char* upath, const char* const* uargv, const char* const* uenvp){
    (void)uenvp;
    if (!upath) return (uint64_t)-14; // -EFAULT
    const char* path = user_cstr(upath);
    uint64_t entry = 0, ustack_top = 0;
    if (elf64_load_process(path, 1 << 20, &entry, &ustack_top) != 0) return (uint64_t)-2; // -ENOENT

    // Copy argv strings (up to 64)
    const int MAX_ARGS = 64; const char* kargv[MAX_ARGS]; size_t alens[MAX_ARGS]; int argc=0;
    if (uargv){
        while (argc < MAX_ARGS){ const char* s = uargv[argc]; if (!s) break; kargv[argc]=s; alens[argc]=strlen(s)+1; argc++; }
    }
    const char env0[] = "PATH=/bin:/usr/bin:/sbin";
    const char env1[] = "HOME=/root";
    const char env2[] = "TERM=linux";
    const char env3[] = "PS1=~ # ";
    uint8_t rnd[16]; uint64_t t = pit_ticks ? pit_ticks : 0x12345678ULL; for (int i=0;i<16;i++){ rnd[i]=(uint8_t)((t>>((i*5)%32))^((uint64_t)(0x9e + 3*i))); }
    uint64_t at_phdr = elf_last_at_phdr, at_phent = elf_last_at_phent, at_phnum = elf_last_at_phnum; uint64_t at_entry = elf_last_at_entry ? elf_last_at_entry : entry;

    uint64_t sp = ustack_top;
    sp -= sizeof(env3); memcpy((void*)sp, env3, sizeof(env3)); uint64_t e3 = sp;
    sp -= sizeof(env2); memcpy((void*)sp, env2, sizeof(env2)); uint64_t e2 = sp;
    sp -= sizeof(env1); memcpy((void*)sp, env1, sizeof(env1)); uint64_t e1 = sp;
    sp -= sizeof(env0); memcpy((void*)sp, env0, sizeof(env0)); uint64_t e0 = sp;

    uint64_t arg_addrs[MAX_ARGS];
    for (int i = argc - 1; i >= 0; --i){ size_t len = alens[i]; sp -= len; memcpy((void*)sp, kargv[i], len); arg_addrs[i] = sp; }

    sp -= sizeof(rnd); memcpy((void*)sp, rnd, sizeof(rnd)); uint64_t at_random_ptr = sp; sp &= ~0xFULL;
    const uint64_t AT_NULL=0, AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_PAGESZ=6, AT_BASE=7, AT_ENTRY=9, AT_UID=11, AT_EUID=12, AT_GID=13, AT_EGID=14, AT_CLKTCK=17, AT_RANDOM=25, AT_SECURE=23, AT_EXECFN=31;
    // argc + argv + NULL + env(4) + NULL + auxv(~16 pairs worst-case we set below)
    size_t vec_qwords = 1 + (size_t)argc + 1 + 4 + 1 + 2*22;
    // Place execfn string on stack
    size_t execfn_len = strlen(path) + 1;
    sp -= execfn_len; memcpy((void*)sp, path, execfn_len); uint64_t execfn_ptr = sp;
    sp &= ~0xFULL;
    sp -= vec_qwords * 8ULL; uint64_t* vec = (uint64_t*)sp; size_t idx=0;
    vec[idx++] = (uint64_t)argc; for (int i=0;i<argc;i++) vec[idx++] = arg_addrs[i]; vec[idx++] = 0;
    vec[idx++] = e0; vec[idx++] = e1; vec[idx++] = e2; vec[idx++] = e3; vec[idx++] = 0;
    vec[idx++] = AT_PHDR; vec[idx++] = at_phdr;
    vec[idx++] = AT_PHENT; vec[idx++] = at_phent;
    vec[idx++] = AT_PHNUM; vec[idx++] = at_phnum;
    vec[idx++] = AT_ENTRY; vec[idx++] = at_entry;
    vec[idx++] = AT_PAGESZ; vec[idx++] = 4096;
    vec[idx++] = AT_BASE;   vec[idx++] = 0;        // no interpreter
    vec[idx++] = AT_UID;    vec[idx++] = 0;
    vec[idx++] = AT_EUID;   vec[idx++] = 0;
    vec[idx++] = AT_GID;    vec[idx++] = 0;
    vec[idx++] = AT_EGID;   vec[idx++] = 0;
    vec[idx++] = AT_CLKTCK; vec[idx++] = 100;
    vec[idx++] = AT_SECURE; vec[idx++] = 0;
    vec[idx++] = AT_EXECFN; vec[idx++] = execfn_ptr;
    vec[idx++] = AT_RANDOM; vec[idx++] = at_random_ptr;
    vec[idx++] = AT_NULL; vec[idx++] = 0;

    // Register new user thread context (name from path)
    const char* base = path; for (const char* p = path; *p; ++p) if (*p=='/') base = p+1;
    thread_register_user(at_entry, sp, base && *base ? base : "user");
    // reset stdio fds to TTY
    thread_t* ut = thread_get_current_user();
    if (ut){
        for (int i=0;i<3;i++) ut->fds[i]=nullptr;
        fs_file_t* f0 = (fs_file_t*)kmalloc(sizeof(fs_file_t)); if (f0){ memset(f0,0,sizeof(*f0)); f0->private_data=&g_tty_private_tag; }
        fs_file_t* f1 = (fs_file_t*)kmalloc(sizeof(fs_file_t)); if (f1){ memset(f1,0,sizeof(*f1)); f1->private_data=&g_tty_private_tag; }
        fs_file_t* f2 = (fs_file_t*)kmalloc(sizeof(fs_file_t)); if (f2){ memset(f2,0,sizeof(*f2)); f2->private_data=&g_tty_private_tag; }
        ut->fds[0]=f0; ut->fds[1]=f1; ut->fds[2]=f2;
    }

    // Request trampoline to new userspace
    exec_new_rip = at_entry;
    exec_new_rsp = sp;
        exec_child_rax = 0;
        exec_trampoline = 1;
    // Reset mmap arena for the new process so future mmaps start above the freshly loaded image
    g_mmap_next = 0;
        return 0;
}

static inline void write_msr(uint32_t msr, uint64_t value){
	uint32_t lo = (uint32_t)(value & 0xFFFFFFFFu);
	uint32_t hi = (uint32_t)(value >> 32);
	asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static inline uint64_t read_msr(uint32_t msr){
	uint32_t lo, hi;
	asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
	return ((uint64_t)hi << 32) | lo;
}

extern "C" uint64_t syscall_entry_c(SyscallFrame* f){
    uint64_t nr = f->nr;
    uint64_t a1 = f->a1, a2 = f->a2, a3 = f->a3, a4 = f->a4, a5 = f->a5, a6 = f->a6;

    PrintfQEMU("syscall_entry_c: nr=%llu a1=%llu a2=%llu a3=%llu a4=%llu a5=%llu a6=%llu\n", nr, a1, a2, a3, a4, a5, a6);
    switch (nr) {
    case LNX_read: {
        int fd = (int)a1; char* buf = (char*)a2; size_t cnt = (size_t)a3;
        fs_file_t* ff = fd_get(fd);
        if (fd_is_tty(ff)) return (uint64_t)console_read(buf, cnt);
        if (!ff) return (uint64_t)-9; // -EBADF
        int r = fs_read(ff, buf, cnt);
        return (uint64_t)r;
    }
    case LNX_write: {
        int fd = (int)a1; const char* buf = (const char*)a2; size_t cnt = (size_t)a3;
        fs_file_t* ff = fd_get(fd);
        if (fd_is_tty(ff)) {
            // Mirror stderr into QEMU log for diagnostics (bounded length)
            if (fd == 2 && buf && cnt){
                size_t show = cnt; if (show > 160) show = 160;
                // Print as a bounded C-string: copy to temp to ensure NUL-termination
                char tmp[161]; size_t i=0; for (; i<show; ++i){ tmp[i] = buf[i]; }
                tmp[i] = '\0';
                PrintfQEMU("[stderr] %s\n", tmp);
            }
            return (uint64_t)console_write(buf, cnt);
        }
        if (!ff) return (uint64_t)-9;
        int r = fs_write(ff, buf, cnt);
        if (r < 0) return (uint64_t)-30; // -EROFS for our initrd
        return (uint64_t)r;
    }
    case LNX_writev: {
        int fd = (int)a1; struct iov { const void* iov_base; uint64_t iov_len; }; const struct iov* iovp = (const struct iov*)a2; int iovcnt = (int)a3; long total = 0;
        fs_file_t* ff = fd_get(fd);
        for (int i=0;i<iovcnt;i++){
            const char* base = (const char*)iovp[i].iov_base; size_t len = (size_t)iovp[i].iov_len;
            long r;
            if (fd_is_tty(ff)) {
                if (fd == 2 && base && len){
                    size_t show = len; if (show > 160) show = 160;
                    char tmp[161]; size_t j=0; for (; j<show; ++j){ tmp[j] = base[j]; }
                    tmp[j] = '\0';
                    PrintfQEMU("[stderr] %s\n", tmp);
                }
                r = console_write(base, len);
            }
            else if (!ff) return (uint64_t)-9;
            else r = fs_write(ff, base, len);
            if (r < 0) return r; total += r;
        }
        return (uint64_t)total;
    }
    case LNX_open: {
        const char* path = user_cstr((const char*)a1); int flags = (int)a2; (void)flags; // read-only FS
        fs_file_t* f = fs_open(path, FS_OPEN_READ);
        if (!f) return (uint64_t)-2; // -ENOENT
        int fd = fd_alloc(f);
        if (fd < 0){ fs_close(f); return (uint64_t)-24; /* -EMFILE */ }
        return (uint64_t)fd;
    }
    case LNX_openat: {
        int dirfd = (int)a1; const char* path = user_cstr((const char*)a2); (void)dirfd; int flags = (int)a3; (void)flags;
        // treat relative to root for simplicity
        fs_file_t* f = fs_open(path, FS_OPEN_READ);
        if (!f) return (uint64_t)-2;
        int fd = fd_alloc(f); if (fd < 0){ fs_close(f); return (uint64_t)-24; }
        return (uint64_t)fd;
    }
    case LNX_close: {
        return (uint64_t)fd_close((int)a1);
    }
    case LNX_lseek: {
        int fd = (int)a1; long off = (long)a2; int wh = (int)a3;
        fs_file_t* f = fd_get(fd); if (!f) return (uint64_t)-9;
        int pos = fs_seek(f, (int)off, wh);
        return (uint64_t)pos;
    }
    case LNX_newfstatat: // newfstatat(dirfd, path, statbuf, flags) → minimal
    case LNX_fstat: {
        // Fill Linux struct stat with minimal fields. We'll zero memory and set mode appropriately.
        void* statbuf = (void*) (nr == LNX_fstat ? a2 : a3);
        memset(statbuf, 0, 256);
        // Try to detect TTY for fstat
        if (nr == LNX_fstat) {
            int fd = (int)a1; fs_file_t* f = fd_get(fd);
            uint32_t mode = fd_is_tty(f) ? 0020000 /*S_IFCHR*/ | 0600 : 0100000 /*S_IFREG*/ | 0400;
            // st_mode at offset 24 on x86_64 linux struct stat
            ((uint32_t*)((uint8_t*)statbuf + 24))[0] = mode;
            // st_nlink at 28
            ((uint64_t*)((uint8_t*)statbuf + 32))[0] = f ? (uint64_t)f->size : 0; // st_ino fake with size
            ((uint64_t*)((uint8_t*)statbuf + 48))[0] = f ? (uint64_t)f->size : 0; // st_size
            return 0;
        } else {
            const char* path = (const char*)a2; fs_stat_t st; if (fs_stat(path, &st) != 0) return (uint64_t)-2; // -ENOENT
            uint32_t mode = (st.attributes & FS_ATTR_DIRECTORY) ? (0040000|0555) : (0100000|0444);
            ((uint32_t*)((uint8_t*)statbuf + 24))[0] = mode;
            ((uint64_t*)((uint8_t*)statbuf + 48))[0] = st.size;
            return 0;
        }
    }
    case LNX_ioctl: {
        int fd = (int)a1; unsigned long req = a2; void* argp = (void*)a3; fs_file_t* f = fd_get(fd);
        if (req == TIOCGWINSZ_ && fd_is_tty(f)){
            struct { unsigned short ws_row, ws_col, ws_x, ws_y; } ws;
            uint32_t w = vbe_console_ready() ? vbec_get_width() : vga_get_width();
            uint32_t h = vbe_console_ready() ? vbec_get_height() : vga_get_height();
            ws.ws_col = (unsigned short)(w / 9);
            ws.ws_row = (unsigned short)(h / 16);
            ws.ws_x = ws.ws_y = 0;
            memcpy(argp, &ws, sizeof(ws));
            return 0;
        }
        return (uint64_t)-25; // -ENOTTY
    }
    case LNX_brk: {
        return sys_brk(a1);
    }
    case LNX_mmap: return sys_mmap(a1,a2,a3,a4,a5,a6);
    case LNX_munmap: return sys_munmap(a1,a2);
    case LNX_mprotect: return 0;
    case LNX_sched_yield: { thread_yield(); return 0; }
    case 35: /*nanosleep old*/ {
        // a1=const struct timespec* req {tv_sec,tv_nsec}
        struct { uint64_t tv_sec; uint64_t tv_nsec; }* ts = (decltype(ts))a1; uint64_t ms = ts ? (ts->tv_sec*1000ULL + ts->tv_nsec/1000000ULL) : 0ULL; thread_sleep((uint32_t)ms); return 0; }
    case LNX_clock_gettime: {
        int clkid = (int)a1; (void)clkid; struct { uint64_t tv_sec; uint64_t tv_nsec; }* ts = (decltype(ts))a2;
        uint64_t ms = pit_get_time_ms(); ts->tv_sec = ms/1000ULL; ts->tv_nsec = (ms%1000ULL)*1000000ULL; return 0;
    }
    case LNX_getpid: {
        thread_t* t = cur_user(); return (uint64_t)(t ? t->tid : 1);
    }
    case LNX_uname: {
        struct uts { char sysname[65]; char nodename[65]; char release[65]; char version[65]; char machine[65]; char domain[65]; };
        uts* u = (uts*)a1; if (!u) return (uint64_t)-14; memset(u,0,sizeof(*u));
        strncpy(u->sysname, "entix", 64); strncpy(u->release, "0.1", 64); strncpy(u->version, "entix-early", 64); strncpy(u->machine, "x86_64", 64); return 0;
    }
    case LNX_getcwd: {
        char* buf = (char*)a1; size_t sz = (size_t)a2; if (!buf || sz==0) return (uint64_t)-22; const char* s = "/"; size_t L = strlen(s)+1; if (L>sz) return (uint64_t)-34; memcpy(buf,s,L); return (uint64_t)L;
    }
    case LNX_chdir: return 0;
    case LNX_access: {
        const char* path = (const char*)a1; fs_stat_t st; return fs_stat(path, &st) == 0 ? 0 : (uint64_t)-2;
    }
    case LNX_readlinkat: {
        int dfd = (int)a1; (void)dfd; const char* path = (const char*)a2; char* buf = (char*)a3; size_t bufsz = (size_t)a4;
        const char* t = vfs_readlink_target(path); if (!t) return (uint64_t)-22;
        size_t L = strlen(t); if (L > bufsz) L = bufsz; memcpy(buf, t, L); return (uint64_t)L;
    }
    case LNX_arch_prctl: {
        int code = (int)a1; uint64_t val = a2;
        const uint32_t IA32_FS_BASE = 0xC0000100;
        PrintfQEMU("[arch_prctl] code=0x%x val=0x%llx\n", code, (unsigned long long)val);
        if (code == ARCH_SET_FS_) {
            uint32_t lo = (uint32_t)(val & 0xFFFFFFFFu); uint32_t hi = (uint32_t)(val >> 32);
            asm volatile("wrmsr" :: "c"(IA32_FS_BASE), "a"(lo), "d"(hi));
            thread_t* t = cur_user(); if (t) t->user_fs_base = val;
            PrintfQEMU("[arch_prctl] FS set to 0x%llx\n", (unsigned long long)val);
            return 0;
        } else if (code == ARCH_GET_FS_) {
            uint32_t lo, hi; asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(IA32_FS_BASE));
            uint64_t* p = (uint64_t*)val; *p = ((uint64_t)hi<<32) | lo; return 0;
        }
        return (uint64_t)-38;
    }
    case LNX_set_tid_address: {
        thread_t* t = cur_user(); if (t) t->clear_child_tid = a1; return (uint64_t)(t ? t->tid : 1);
    }
    case LNX_execve: {
        return sys_execve_kernel((const char*)a1, (const char* const*)a2, (const char* const*)a3);
    }
    case LNX_exit:
    case LNX_exit_group: {
        int code = (int)a1;
        thread_t* user = thread_get_current_user();
        if (user) {
            g_exit_code[(int)user->tid] = code;
            g_stopped[(int)user->tid] = 1;
            thread_stop((int)user->tid);
            thread_set_current_user(nullptr);
                } else {
            thread_t* cur = thread_current();
            if (cur && cur->tid != 0) {
                thread_stop(cur->tid);
            }
        }
        kprintf("cycle");
        for(;;) { thread_yield(); }
    }
    default:
        PrintfQEMU("[syscall] unimplemented nr=%llu a1=0x%llx a2=0x%llx a3=0x%llx\n", (unsigned long long)nr, (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);
        return (uint64_t)-38; // -ENOSYS
    }
}

void syscall_x64_init(){
	const uint32_t IA32_EFER  = 0xC0000080;
	const uint32_t IA32_STAR  = 0xC0000081;
	const uint32_t IA32_LSTAR = 0xC0000082;
	const uint32_t IA32_FMASK = 0xC0000084;

	// Enable SYSCALL in EFER
	uint64_t efer = read_msr(IA32_EFER);
	efer |= 1ULL; // SCE
	write_msr(IA32_EFER, efer);

	// Program STAR: upper holds user CS, lower holds kernel CS
	uint64_t star = ((uint64_t)USER_CS << 48) | ((uint64_t)KERNEL_CS << 32);
	write_msr(IA32_STAR, star);

	// Program LSTAR with entry point
	write_msr(IA32_LSTAR, (uint64_t)(void*)syscall_entry);

	// Mask IF|DF on entry (clear those bits in RFLAGS)
	write_msr(IA32_FMASK, 0x300ULL);
}

extern "C" void syscall_dispatch(cpu_registers_t* regs) {
	(void)regs; // int 0x80 — заглушка (не используется в x86_64 ABI)
}

extern "C" void syscall_isr(cpu_registers_t* regs) {
        syscall_dispatch(regs);
}

void syscall_init() {
        idt_set_gate(0x80, isr_stub_table[0x80], 0x08, 0xEE); // present | DPL=3 | interrupt gate
        idt_set_handler(0x80, syscall_isr);
} 