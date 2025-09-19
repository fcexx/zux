#include <syscall.h>
#include <thread.h>
#include <vbetty.h>
#include <debug.h>
#include <fs_interface.h>
#include <gdt.h>
#include <stdint.h>
#include <string.h>
#include <pit.h>
#include <paging.h>
#include <heap.h>
#include <elf.h>
#include <stddef.h>

extern "C" { uint64_t syscall_kernel_rsp0 = 0; } // обновляется в tss_set_rsp0
extern "C" void syscall_entry();             // из assembly
extern "C" uint64_t exec_new_rip = 0;        // для trampolining из asm
extern "C" uint64_t exec_new_rsp = 0;        // для trampolining из asm
extern "C" volatile uint64_t exec_trampoline = 0; // флаг для asm: выполнять trampolining
extern "C" uint64_t exec_child_rax = 0;      // значение RAX в ребёнке после trampolining
extern "C" uint64_t syscall_saved_user_rsp = 0; // сохраняется в asm на входе SYSCALL
extern "C" uint64_t syscall_saved_user_rcx = 0; // сохраняется в asm на входе SYSCALL

// Forward declarations of local syscall helpers defined below
static void sys_yield();
static long sys_write(int fd, const char* buf, unsigned long len);
static void sys_exit(int code);
static long sys_open(const char* path, int flags);
static long sys_read(int fd, void* buf, unsigned long len);
static long sys_close(int fd);
static long sys_seek(int fd, int off, int whence);
static long sys_writev(int fd, const void* iov, unsigned long iovcnt);
static void sys_sleep(unsigned long ms);
static long sys_poll(void* fds_user, unsigned long nfds, int timeout_ms);
static long sys_openat(int dirfd, const char* path, int flags, int mode);
static long sys_stat_path(const char* path, void* user_stat);
static long sys_lstat_path(const char* path, void* user_stat);
static long sys_fstat_fd(int fd, void* user_stat);
static long sys_newfstatat(int dirfd, const char* path, void* user_stat, int flags);
static long sys_getcwd(char* buf, unsigned long size);
static long sys_chdir(const char* path);
static long sys_getpid();
static long sys_getppid();
static long sys_vfork();
static long sys_wait4(int pid, int* status, int options, void* rusage);
static long sys_getdents64(int fd, void* dirp, unsigned long count);
static long sys_uname(void* uts);
static long sys_gettimeofday(void* tv, void* tz);
static long sys_clock_gettime(int clockid, void* ts);
static long sys_nanosleep(const void* req, void* rem);
static uint64_t sys_mmap_impl(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t /*fd*/, uint64_t /*off*/);
static uint64_t sys_mremap_impl(uint64_t old_addr, uint64_t old_len, uint64_t new_len, uint64_t flags, uint64_t new_addr);
static long sys_madvise(uint64_t addr, uint64_t len, int advice);
static long sys_mprotect_impl(uint64_t /*addr*/, uint64_t /*len*/, uint64_t /*prot*/);
static long sys_munmap_impl(uint64_t /*addr*/, uint64_t /*len*/);
static long sys_brk_impl(uint64_t newbrk);
extern "C" uint64_t sys_execve(const char* path, const char* const* argv, const char* const* envp);
static long sys_arch_prctl(long code, uint64_t addr);
static long sys_set_tid_address(uint64_t tidptr);
static long sys_futex(uint64_t /*uaddr*/, int /*op*/, uint64_t /*val*/, uint64_t /*timeout*/, uint64_t /*uaddr2*/, uint64_t /*val3*/);
static long sys_access(const char* path, int /*mode*/);
static long sys_readlink(const char* path, char* buf, unsigned long bufsz);
static long sys_unlink(const char* /*path*/);
static long sys_mkdir(const char* /*path*/, int /*mode*/);
// --- TTY support (/dev/tty) ---
extern "C" char g_tty_private_tag;
static inline bool is_tty_file(fs_file_t* f){ return f && f->private_data == &g_tty_private_tag; }
static inline thread_t* active_thread(){ thread_t* u = thread_get_current_user(); return u ? u : thread_current(); }
static inline bool is_tty_fd(int fd){ thread_t* t = active_thread(); return t && fd >= 0 && fd < THREAD_MAX_FD && is_tty_file(t->fds[fd]); }
static long sys_rmdir(const char* /*path*/);
static long sys_rename(const char* /*oldp*/, const char* /*newp*/);
static long sys_truncate(const char* /*path*/, long /*length*/);
static long sys_ftruncate(int /*fd*/, unsigned long /*length*/);
// console/tty-aware ioctl
static long sys_ioctl(int fd, unsigned int cmd, unsigned long arg);
static long sys_umask(int mode);
static long sys_getuid();
static long sys_geteuid();
static long sys_getgid();
static long sys_getegid();
static long sys_gettid();
static long sys_getrlimit(int /*resource*/, void* rlim_user);
static long sys_prlimit64(int /*pid*/, int /*resource*/, const void* /*new_limit*/, void* /*old_limit*/);
static long sys_set_robust_list(void* /*head*/, size_t /*len*/);
static long sys_prctl(long /*option*/, unsigned long /*arg2*/, unsigned long /*arg3*/, unsigned long /*arg4*/, unsigned long /*arg5*/);
static long sys_faccessat(int dirfd, const char* path, int mode, int /*flags*/);


// console I/O helpers and tty constants
extern "C" char kgetc();
extern "C" int kgetc_available();
struct linux_winsize { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; };
static constexpr unsigned int LINUX_TCGETS = 0x5401;
static constexpr unsigned int LINUX_TIOCGWINSZ = 0x5413;

// --- Minimal process bookkeeping (used by sys_exit/wait4) ---
static int g_parent_of[256] = {0}; // parent pid for simple wait4
static int g_exit_code[256] = {0};
static volatile int g_stopped[256] = {0};

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
    uint64_t nr_raw = nr;
    // Нормализуем номер: отбрасываем верхние 32 бита и возможный префикс 0x200000 (BSD/Darwin стиль)
    nr &= 0xFFFFFFFFull;
    if ((nr & 0xFFF00000ull) == 0x00200000ull) nr &= 0x000FFFFFull;
    // Поддержка Linux x32 ABI: системные вызовы пронумерованы "базовый+512"
    if (nr >= 512 && nr < 1024) nr -= 512;
    //PrintfQEMU("syscall num: %u\n", nr);
    switch (nr) {
        case 58: /* vfork */ return (uint64_t)sys_vfork();
        case 61: /* wait4  */ return (uint64_t)sys_wait4((int)f->a1, (int*)f->a2, (int)f->a3, (void*)f->a4);
        // Linux x86_64 ABI core
        case 0:  /* read   */ return (uint64_t)sys_read((int)f->a1, (void*)f->a2, f->a3);
        case 1:  /* write  */ return (uint64_t)sys_write((int)f->a1, (const char*)f->a2, f->a3);
        case 2:  /* open   */ return (uint64_t)sys_open((const char*)f->a1, (int)f->a2);
        case 3:  /* close  */ return (uint64_t)sys_close((int)f->a1);
        case 4:  /* stat   */ return (uint64_t)sys_stat_path((const char*)f->a1, (void*)f->a2);
        case 5:  /* fstat  */ return (uint64_t)sys_fstat_fd((int)f->a1, (void*)f->a2);
        case 6:  /* lstat  */ return (uint64_t)sys_lstat_path((const char*)f->a1, (void*)f->a2);
        case 7:  /* poll */ return (uint64_t)sys_poll((void*)f->a1, f->a2, (int)f->a3);
        case 8:  /* lseek  */ return (uint64_t)sys_seek((int)f->a1, (int)f->a2, (int)f->a3);
        case 9:   /* mmap   */ return (uint64_t)sys_mmap_impl(f->a1, f->a2, f->a3, f->a4, f->a5, f->a6);
        case 10:  /* mprotect */ return (uint64_t)sys_mprotect_impl(f->a1, f->a2, f->a3);
        case 11:  /* munmap */ return (uint64_t)sys_munmap_impl(f->a1, f->a2);
        case 12: /* brk    */ return (uint64_t)sys_brk_impl(f->a1);
        case 13: /* rt_sigaction (stub) */ return 0;
        case 14: /* rt_sigprocmask (stub) */ return 0;
        case 20: /* writev */ return (uint64_t)sys_writev((int)f->a1, (const void*)f->a2, f->a3);
        case 16: /* ioctl (stub) */ return (uint64_t)sys_ioctl((int)f->a1, (unsigned int)f->a2, f->a3);
        case 21: /* access */ return (uint64_t)sys_access((const char*)f->a1, (int)f->a2);
        case 24: /* sched_yield */ sys_yield(); return 0;
        case 28: /* madvise */ return (uint64_t)sys_madvise(f->a1, f->a2, (int)f->a3);
        case 25: /* mremap */ return (uint64_t)sys_mremap_impl(f->a1, f->a2, f->a3, f->a4, f->a5);
        case 35: /* nanosleep */ return (uint64_t)sys_nanosleep((const void*)f->a1, (void*)f->a2);
        case 39: /* getpid */ return (uint64_t)sys_getpid();
        case 59: /* execve */ return (uint64_t)sys_execve((const char*)f->a1, (const char* const*)f->a2, (const char* const*)f->a3);
        case 60: /* exit   */ sys_exit((int)f->a1); return 0;
        case 63: /* uname  */ return (uint64_t)sys_uname((void*)f->a1);
        case 70: /* stub (compat) */ return 0;
        case 72: /* fcntl (stub)  */ return 0;
        case 76: /* truncate (stub) */ return (uint64_t)sys_truncate((const char*)f->a1, (long)f->a2);
        case 77: /* ftruncate (stub) */ return (uint64_t)sys_ftruncate((int)f->a1, f->a2);
        case 79: /* getcwd */ return (uint64_t)sys_getcwd((char*)f->a1, f->a2);
        case 80: /* chdir  */ return (uint64_t)sys_chdir((const char*)f->a1);
        case 82: /* rename (ro fs) */ return (uint64_t)sys_rename((const char*)f->a1, (const char*)f->a2);
        case 83: /* mkdir (ro fs)  */ return (uint64_t)sys_mkdir((const char*)f->a1, (int)f->a2);
        case 84: /* rmdir (ro fs)  */ return (uint64_t)sys_rmdir((const char*)f->a1);
        case 87: /* unlink (ro fs) */ return (uint64_t)sys_unlink((const char*)f->a1);
        case 89: /* readlink */ return (uint64_t)sys_readlink((const char*)f->a1, (char*)f->a2, f->a3);
        case 90: /* chmod (stub) */ return 0;
        case 91: /* fchmod (stub) */ return 0;
        case 92: /* chown (stub) */ return 0;
        case 93: /* fchown (stub) */ return 0;
        case 94: /* lchown (stub) */ return 0;
        case 95: /* umask */ return (uint64_t)sys_umask((int)f->a1);
        case 96: /* gettimeofday */ return (uint64_t)sys_gettimeofday((void*)f->a1, (void*)f->a2);
        case 97: /* getrlimit */ return (uint64_t)sys_getrlimit((int)f->a1, (void*)f->a2);
        case 102: /* getuid */ return (uint64_t)sys_getuid();
        case 104: /* getgid */ return (uint64_t)sys_getgid();
        case 107: /* geteuid */ return (uint64_t)sys_geteuid();
        case 108: /* getegid */ return (uint64_t)sys_getegid();
        case 110: /* getppid */ return (uint64_t)sys_getppid();
        case 114: /* setregid (stub) */ return 0;
        case 115: /* getgroups (stub) */ return 0;
        case 116: /* setgroups (stub) */ return 0;
        case 117: /* setresuid (stub) */ return 0;
        case 118: /* getresuid (stub) */ return 0;
        case 119: /* setresgid (stub) */ return 0;
        case 120: /* getresgid (stub) */ return 0;
        case 146: /* sched_get_priority_max (stub) */ return 0;
        case 147: /* sched_get_priority_min (stub) */ return 0;
        case 157: /* prctl (stub) */ return (uint64_t)sys_prctl((long)f->a1, f->a2, f->a3, f->a4, f->a5);
        case 158: /* arch_prctl */ return (uint64_t)sys_arch_prctl((long)f->a1, f->a2);
        case 160: /* setrlimit (stub) */ return 0;
        case 186: /* gettid */ return (uint64_t)sys_gettid();
        case 202: /* futex (stub) */ return (uint64_t)sys_futex(f->a1, (int)f->a2, f->a3, f->a4, f->a5, f->a6);
        case 217: /* getdents64 */ return (uint64_t)sys_getdents64((int)f->a1, (void*)f->a2, f->a3);
        case 218: /* set_tid_address */ return 0;
        case 219: /* restart_syscall (stub) */ return 0;
        case 228: /* clock_gettime */ return (uint64_t)sys_clock_gettime((int)f->a1, (void*)f->a2);
        case 231: /* exit_group */ sys_exit((int)f->a1); return 0;
        case 257: /* openat */ return (uint64_t)sys_openat((int)f->a1, (const char*)f->a2, (int)f->a3, (int)f->a4);
        case 262: /* newfstatat */ return (uint64_t)sys_newfstatat((int)f->a1, (const char*)f->a2, (void*)f->a3, (int)f->a4);
        case 268: /* fchmodat (stub) */ return 0;
        case 269: /* faccessat */ return (uint64_t)sys_faccessat((int)f->a1, (const char*)f->a2, (int)f->a3, (int)f->a4);
        case 273: /* set_robust_list */ return (uint64_t)sys_set_robust_list((void*)f->a1, (size_t)f->a2);
        case 302: /* prlimit64 */ return (uint64_t)sys_prlimit64((int)f->a1, (int)f->a2, (const void*)f->a3, (void*)f->a4);
        case 318: /* getrandom (stub) */ {
            uint8_t* p = (uint8_t*)f->a1; unsigned long n = f->a2;
            if (!p) return -22;
            for (unsigned long i=0;i<n;i++) p[i]=(uint8_t)((pit_ticks>>((i*7)%32))^0x5a);
            return (long)n; }
        default:
            PrintfQEMU("syscall64: unknown nr=%llu (raw=%llu)\n", (unsigned long long)nr, (unsigned long long)nr_raw);
            return (uint64_t)-38; // -ENOSYS
    }
}

void syscall_x64_init(){
    // MSR indices
    const uint32_t IA32_EFER  = 0xC0000080;
    const uint32_t IA32_STAR  = 0xC0000081;
    const uint32_t IA32_LSTAR = 0xC0000082;
    const uint32_t IA32_FMASK = 0xC0000084;

    // Enable SYSCALL in EFER
    uint64_t efer = read_msr(IA32_EFER);
    efer |= 1ULL; // SCE
    write_msr(IA32_EFER, efer);
    PrintfQEMU("[syscall] EFER set: 0x%llx\n", (unsigned long long)efer);

    // Program STAR: upper holds user CS, lower holds kernel CS
    uint64_t star = ((uint64_t)USER_CS << 48) | ((uint64_t)KERNEL_CS << 32);
    write_msr(IA32_STAR, star);
    PrintfQEMU("[syscall] STAR written: 0x%llx\n", (unsigned long long)star);

    // Program LSTAR with entry point
    write_msr(IA32_LSTAR, (uint64_t)(void*)syscall_entry);
    PrintfQEMU("[syscall] LSTAR=0x%llx\n", (unsigned long long)(uint64_t)(void*)syscall_entry);

    // Mask IF|DF on entry (clear those bits in RFLAGS). Keep TF off too optionally.
    write_msr(IA32_FMASK, 0x300ULL);
    PrintQEMU("[syscall] FMASK written\n");

    PrintfQEMU("[syscall] STAR=0x%llx LSTAR=0x%llx EFER=0x%llx\n",
        (unsigned long long)star,
        (unsigned long long)(uint64_t)(void*)syscall_entry,
        (unsigned long long)efer);
}

static void sys_yield() { thread_yield(); }

static long sys_write(int fd, const char* buf, unsigned long len){
    PrintfQEMU("[write] fd=%d buf=0x%llx len=%llu\n", fd, (unsigned long long)(uint64_t)buf, (unsigned long long)len);
    if (fd == 1 || fd == 2 || is_tty_fd(fd)) {
        if (!buf || len == 0) return 0;
        auto put_tty_char = [](char c){
            if (c == '\r') { int y = vbetty_get_cursor_y(); vbetty_set_cursor_pos(0, y); return; }
            if (c == '\b' || c == 127) { int x=vbetty_get_cursor_x(); int y=vbetty_get_cursor_y(); if (x>0) vbetty_set_cursor_pos(x-1,y); return; }
            vbetty_put_char(c);
        };
        // Диагностика для fd==1: краткий предпросмотр и счётчик повторов
        if (fd == 1) {
            static const char hex[] = "0123456789ABCDEF";
            static const void* last_buf = nullptr; static unsigned long last_len = 0; static unsigned long repeat = 0;
            if (buf == last_buf && len == last_len) {
                repeat++;
                if ((repeat % 64) == 0) {
                    extern uint64_t syscall_saved_user_rcx;
                    uint64_t rip = syscall_saved_user_rcx;
                    // снимем несколько байт кода по адресу RIP
                    unsigned char op[8] = {0};
                    for (int i=0;i<8;i++) op[i] = ((volatile unsigned char*)rip)[i];
                    PrintfQEMU("[write1] repeat x%lu same buf=%p len=%lu caller=0x%llx op=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                        repeat, last_buf, last_len, (unsigned long long)rip,
                        op[0],op[1],op[2],op[3],op[4],op[5],op[6],op[7]);
                }
            } else {
                repeat = 0; last_buf = buf; last_len = len;
                unsigned long n = len < 64 ? len : 64;
                char out[3*64 + 1]; unsigned long j=0;
                for (unsigned long i=0;i<n;i++){
                    unsigned char c = (unsigned char)buf[i];
                    if (c=='\n' || (c>=32 && c<127)) {
                        // печатаем как текст
                        PrintfQEMU("[write1] preview: ");
                        for (unsigned long k=0;k<n;k++){
                            unsigned char cc=(unsigned char)buf[k];
                            PrintfQEMU("%c", (cc=='\n'||(cc>=32&&cc<127))?cc:'.');
                        }
                        PrintfQEMU("\n");
                        break;
                    } else {
                        // если бинарщина — один раз покажем hex-дамп
                        out[j++] = hex[(c>>4)&0xF]; out[j++] = hex[c&0xF]; out[j++] = ' ';
                    }
                }
                if (j) { out[j?j-1:0] = '\0'; PrintfQEMU("[write1] hex: %s\n", out); }
            }
        }
        // stderr (fd==2) больше не дублируем в консоль и лог, просто печатаем ниже общей петлёй
        for (unsigned long i = 0; i < len; ++i) put_tty_char(buf[i]);
        return (long)len;
    }
    return -1;
}

struct linux_iovec { const void* iov_base; uint64_t iov_len; };

static long sys_writev(int fd, const void* iov, unsigned long iovcnt){
    PrintfQEMU("[writev] fd=%d iov=0x%llx cnt=%llu\n", fd, (unsigned long long)(uint64_t)iov, (unsigned long long)iovcnt);
    if (!iov || iovcnt == 0) return 0;
    const linux_iovec* vec = (const linux_iovec*)iov;
    if (iovcnt > 1024) iovcnt = 1024; // простая защита
    long total = 0;
    for (unsigned long i = 0; i < iovcnt; ++i){
        const char* base = (const char*)vec[i].iov_base;
        unsigned long len = (unsigned long)vec[i].iov_len;
        if (!base || len == 0) continue;
        PrintfQEMU("[writev] part[%llu] base=0x%llx len=%llu\n", (unsigned long long)i, (unsigned long long)(uint64_t)base, (unsigned long long)len);
        long r = sys_write(fd, base, len);
        if (r < 0) return (total > 0) ? total : r;
        total += r;
        if ((unsigned long)r < len) break; // частичная запись
    }
    return total;
}

static void sys_exit(int code) {
    (void)code;
    thread_t* user = thread_get_current_user();
    if (user) {
        PrintfQEMU("[exit] pid=%d name=%s code=%d\n", (int)user->tid, user->name, code);
        g_exit_code[(int)user->tid] = code;
        g_stopped[(int)user->tid] = 1;
        thread_stop((int)user->tid);
        thread_set_current_user(nullptr);
    } else {
        thread_t* cur = thread_current();
        if (cur) {
            PrintfQEMU("[exit] kernel-thread pid=%d name=%s code=%d\n", (int)cur->tid, cur->name, code);
            // Никогда не останавливаем idle (pid==0)
            if (cur->tid != 0) {
                thread_stop(cur->tid);
            } else {
                PrintfQEMU("[exit] ignore stop for idle thread\n");
            }
        } else {
            PrintfQEMU("[exit] unknown-thread code=%d\n", code);
        }
    }
    // Никогда не возвращаемся в ring3 после выхода процесса
    for(;;) { thread_yield(); }
}

static int alloc_fd(thread_t* t, fs_file_t* f){
    for(int i=0;i<THREAD_MAX_FD;i++) if(!t->fds[i]){ t->fds[i]=f; return i; }
    return -1;
}

static long sys_open(const char* path, int flags){
    if(!path) return -1;
    // Special case: /dev/tty — controlling terminal
    if (strcmp(path, "/dev/tty") == 0){
        fs_file_t* f = (fs_file_t*)kmalloc(sizeof(fs_file_t));
        if (!f) return -12; // -ENOMEM
        memset(f, 0, sizeof(*f));
        f->private_data = &g_tty_private_tag;
        f->mode = flags;
        int fd = alloc_fd(active_thread(), f);
        if (fd < 0) { kfree(f); return -24; } // -EMFILE
        return fd;
    }
    fs_file_t* f = fs_open(path, flags);
    if(!f) return -1;
    int fd = alloc_fd(active_thread(), f);
    if(fd<0){ fs_close(f); return -1; }
    return fd;
}

static long sys_read(int fd, void* buf, unsigned long len){
    PrintfQEMU("[read] fd=%d buf=0x%llx len=%llu\n", fd, (unsigned long long)(uint64_t)buf, (unsigned long long)len);
    // stdin or /dev/tty from keyboard buffer
    if ((fd == 0 || is_tty_fd(fd)) && buf && len > 0) {
        unsigned long i = 0;
        for (;;) {
            if (kgetc_available() == 0) {
                if (i > 0) return (long)i; // частичное чтение
                // Разрешим прерывания и подождём IRQ, чтобы клавиатура/PIT могли сработать
                asm volatile("sti; hlt");
                continue;
            }
            char c = kgetc();
            reinterpret_cast<char*>(buf)[i++] = c;
            // Возврат по достижению лимита или по переводу строки
            kprintf("%c", c);
            if (i >= len || c == '\n') return (long)i;
            if (kgetc_available() == 0) return (long)i; // отдаём то, что есть
        }
    }
    thread_t* t = active_thread();
    if(fd<0 || fd>=THREAD_MAX_FD || !t->fds[fd] || !buf) return -1;
    return fs_read(t->fds[fd], buf, len);
}

static long sys_close(int fd){
    thread_t* t = active_thread();
    if(fd<0 || fd>=THREAD_MAX_FD || !t->fds[fd]) return -1;
    fs_file_t* f = t->fds[fd];
    if (is_tty_file(f)) { kfree(f); t->fds[fd]=nullptr; return 0; }
    int r = fs_close(f);
    t->fds[fd]=nullptr;
    return r;
}

static long sys_seek(int fd, int off, int whence){
    thread_t* t = active_thread();
    if(fd<0 || fd>=THREAD_MAX_FD || !t->fds[fd]) return -1;
    if (is_tty_file(t->fds[fd])) return -29; // -ESPIPE
    return fs_seek(t->fds[fd], off, whence);
}

static void sys_sleep(unsigned long ms){
    thread_sleep((uint32_t)ms);
}

// Минимальная реализация poll(2): поддержка POLLIN/POLLOUT, /dev/tty
static long sys_poll(void* fds_user, unsigned long nfds, int timeout_ms){
    if (!fds_user || nfds == 0) return 0;
    struct pollfd_linux { int fd; short events; short revents; };
    const short POLLIN = 0x0001; const short POLLOUT = 0x0004; const short POLLERR = 0x0008;
    pollfd_linux* fds = (pollfd_linux*)fds_user;
    auto compute_ready = [&]()->unsigned long{
        unsigned long ready = 0;
        thread_t* t = active_thread();
        for (unsigned long i=0;i<nfds;i++){
            int fd = fds[i].fd; short ev = fds[i].events; fds[i].revents = 0;
            if (fd < 0 || fd >= THREAD_MAX_FD || !t->fds[fd]) { fds[i].revents |= POLLERR; continue; }
            if (is_tty_file(t->fds[fd])){
                if ((ev & POLLIN) && kgetc_available()) fds[i].revents |= POLLIN;
                if (ev & POLLOUT) fds[i].revents |= POLLOUT;
            } else {
                if (ev & POLLIN) fds[i].revents |= POLLIN;
                if (ev & POLLOUT) fds[i].revents |= POLLOUT;
            }
            if (fds[i].revents) ready++;
        }
        return ready;
    };
    unsigned long r = compute_ready();
    if (r > 0) return (long)r;
    if (timeout_ms == 0) return 0;
    uint64_t start = pit_ticks;
    for(;;){
        r = compute_ready();
        if (r > 0) return (long)r;
        if (timeout_ms > 0) {
            uint64_t elapsed = pit_ticks - start;
            if (elapsed >= (uint64_t)timeout_ms) return 0;
        }
        thread_sleep(1);
    }
}

// Minimal openat implementation: support AT_FDCWD (-100) or absolute path
static long sys_openat(int dirfd, const char* path, int flags, int /*mode*/){
    const int AT_FDCWD = -100;
    if (!path) return -22; // -EINVAL
    // We do not support directory FDs yet; accept AT_FDCWD or absolute path
    if (dirfd != AT_FDCWD && path[0] != '/') return -9; // -EBADF (or -ENOTSUP)
    if (strcmp(path, "/dev/tty") == 0){
        fs_file_t* f = (fs_file_t*)kmalloc(sizeof(fs_file_t));
        if (!f) return -12; // -ENOMEM
        memset(f, 0, sizeof(*f));
        f->private_data = &g_tty_private_tag;
        f->mode = flags;
        int fd = alloc_fd(active_thread(), f);
        if (fd < 0) { kfree(f); return -24; } // -EMFILE
        return fd;
    }
    fs_file_t* f = fs_open(path, flags);
    if (!f) return -2; // -ENOENT
    int fd = alloc_fd(active_thread(), f);
    if (fd < 0) { fs_close(f); return -24; } // -EMFILE
    return fd;
}

// --- Linux compatibility helpers ---
// Very simplified Linux x86_64 stat layout
struct linux_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t __pad0;
    uint64_t st_rdev;
    int64_t  st_size;
    int64_t  st_blksize;
    int64_t  st_blocks;
    int64_t  st_atime;
    uint64_t st_atime_nsec;
    int64_t  st_mtime;
    uint64_t st_mtime_nsec;
    int64_t  st_ctime;
    uint64_t st_ctime_nsec;
    int64_t  __unused[3];
};

static uint32_t fs_attrs_to_mode(uint32_t attrs){
    const uint32_t S_IFDIR = 0040000;
    const uint32_t S_IFREG = 0100000;
    const uint32_t PERM_DIR = 0755;
    // Разрешим исполняемость обычных файлов по умолчанию (для applets busybox и т.п.)
    const uint32_t PERM_REG = 0755;
    if (attrs & FS_ATTR_DIRECTORY) return S_IFDIR | PERM_DIR;
    return S_IFREG | PERM_REG;
}

static void fill_linux_stat_from_fs(const fs_stat_t* st, struct linux_stat* out){
    memset(out, 0, sizeof(*out));
    out->st_size = (int64_t)st->size;
    out->st_mode = fs_attrs_to_mode(st->attributes);
    out->st_nlink = 1;
    out->st_blksize = 4096;
}

static void fill_linux_stat_tty(struct linux_stat* out){
    memset(out, 0, sizeof(*out));
    const uint32_t S_IFCHR = 0020000;
    out->st_mode = S_IFCHR | 0666;
    out->st_nlink = 1;
    out->st_blksize = 4096;
}

static long sys_stat_path(const char* path, void* user_stat){
    if (!path || !user_stat) return -22;
    if (strcmp(path, "/dev/tty") == 0){
        struct linux_stat* ls = (struct linux_stat*)user_stat;
        fill_linux_stat_tty(ls);
        return 0;
    }
    fs_stat_t st;
    if (fs_stat(path, &st) != 0) return -2; // -ENOENT
    struct linux_stat* ls = (struct linux_stat*)user_stat;
    fill_linux_stat_from_fs(&st, ls);
    return 0;
}

static long sys_lstat_path(const char* path, void* user_stat){
    // No symlinks in our FS yet; same as stat
    return sys_stat_path(path, user_stat);
}

static long sys_fstat_fd(int fd, void* user_stat){
    thread_t* t = active_thread();
    if (!t || fd < 0 || fd >= THREAD_MAX_FD || !t->fds[fd] || !user_stat) return -9;
    fs_file_t* f = t->fds[fd];
    struct linux_stat* ls = (struct linux_stat*)user_stat;
    if (is_tty_file(f)) { fill_linux_stat_tty(ls); return 0; }
    fs_stat_t st; memset(&st, 0, sizeof(st));
    st.size = f->size;
    // Attributes unknown from handle; assume regular file
    st.attributes = 0;
    fill_linux_stat_from_fs(&st, ls);
    return 0;
}

static long sys_newfstatat(int dirfd, const char* path, void* user_stat, int /*flags*/){
    const int AT_FDCWD = -100;
    if (!path || !user_stat) return -22;
    if (dirfd != AT_FDCWD && path[0] != '/') return -9; // not supported yet
    return sys_stat_path(path, user_stat);
}

static long sys_getcwd(char* buf, unsigned long size){
    if (!buf || size == 0) return -22;
    if (size < 2) return -34; // -ERANGE
    buf[0] = '/';
    buf[1] = '\0';
    return (long)1; // length
}

static long sys_chdir(const char* path){
    if (!path) return -22;
    // Пока поддерживаем только корень
    if (path[0] == '/' && path[1] == '\0') return 0;
    // Проверим существование каталога простым stat и флагом DIRECTORY
    fs_stat_t st;
    if (fs_stat(path, &st) != 0) return -2; // -ENOENT
    if (!(st.attributes & FS_ATTR_DIRECTORY)) return -20; // -ENOTDIR
    return 0;
}

static long sys_getpid(){
    thread_t* t = thread_current();
    return t ? (long)t->tid : 1;
}

static long sys_getppid(){
    return 1;
}

// --- Minimal process table on top of thread_t ---

static long sys_vfork(){
    thread_t* parent = thread_get_current_user();
    if (!parent) return -38; // -ENOSYS if no user thread
    // Child shares address space and FDs; we reuse current thread as child context via exec trampoline
    // Save parent pid and mark for wait
    int ppid = (int)parent->tid;
    // Child will run at same RIP/RSP after return to userspace; set tramp to just deliver RAX=0
    exec_new_rip = parent->user_rip; exec_new_rsp = parent->user_stack; exec_child_rax = 0; exec_trampoline = 1;
    // Return child's pid to parent in RAX after iret (handled on next syscall return path)
    // For simplicity, use same pid; real fork would allocate new. Minimal hush uses vfork+execve immediately.
    return (long)ppid; // parent sees pid, child sees 0 via exec_child_rax
}

static long sys_wait4(int pid, int* status, int /*options*/, void* /*rusage*/){
    thread_t* me = thread_get_current_user(); (void)me;
    // Minimal stub: just return immediately with pid if thread terminated flag is set via sys_exit
    if (pid <= 0) pid = 2; // default user pid
    // Busy loop with sleep until thread_get_state says TERMINATED
    for(;;){
        int st = thread_get_state(pid);
        if (st == THREAD_TERMINATED){ if (status) *status = g_exit_code[pid]; return pid; }
        thread_sleep(1);
    }
}

// linux_dirent64 structure for getdents64
struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

static long sys_getdents64(int fd, void* dirp, unsigned long count){
    if (!dirp || count < sizeof(linux_dirent64) + 2) return -22; // -EINVAL
    thread_t* t = thread_current();
    if (!t || fd < 0 || fd >= THREAD_MAX_FD || !t->fds[fd]) return -9; // -EBADF

    // Попробуем прочитать директорию по пути из открытого файла (если это файл — вернём -ENOTDIR)
    fs_file_t* file = t->fds[fd];
    struct fat32_fs_file { uint32_t first_cluster, current_cluster, position, size; char path[256]; };
    const char* path = nullptr;
    if (file->private_data) {
        fat32_fs_file* f = (fat32_fs_file*)file->private_data;
        path = f->path;
    }
    if (!path) return -20; // -ENOTDIR

    fs_dir_t* dir = fs_opendir(path);
    if (!dir) return -2; // -ENOENT

    uint8_t* out = (uint8_t*)dirp;
    unsigned long bytes = 0;
    fs_dirent_t ent;
    while (true){
        int r = fs_readdir(dir, &ent);
        if (r != 0) break;
        size_t name_len = strnlen(ent.name, sizeof(ent.name));
        size_t rec_len = sizeof(linux_dirent64) + name_len + 1; // +NUL
        // Align to 8 bytes
        size_t rec_len_aligned = (rec_len + 7) & ~7ULL;
        if (bytes + rec_len_aligned > count) break;

        linux_dirent64* de = (linux_dirent64*)(out + bytes);
        de->d_ino = 1; // fake inode
        de->d_off = (int64_t)(bytes + rec_len_aligned);
        de->d_reclen = (unsigned short)rec_len_aligned;
        de->d_type = (ent.attributes & FS_ATTR_DIRECTORY) ? 4 /*DT_DIR*/ : 8 /*DT_REG*/;
        memcpy(de->d_name, ent.name, name_len);
        de->d_name[name_len] = '\0';
        // zero padding for alignment already in buffer from prior use not guaranteed; explicitly zero
        size_t pad = rec_len_aligned - rec_len;
        if (pad) memset((uint8_t*)de + rec_len, 0, pad);
        bytes += rec_len_aligned;
    }
    fs_closedir(dir);
    return (long)bytes;
}

// uname(2)
struct linux_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

static long sys_uname(void* uts){
    if (!uts) return -22;
    linux_utsname* u = (linux_utsname*)uts;
    memset(u, 0, sizeof(*u));
    strcpy(u->sysname, "Solar");
    strcpy(u->nodename, "localhost");
    strcpy(u->release, "0.0");
    strcpy(u->version, "SolarOS");
    strcpy(u->machine, "x86_64");
    // domainname left empty
    return 0;
}

// gettimeofday(2)
struct linux_timeval { long tv_sec; long tv_usec; };

static long sys_gettimeofday(void* tv, void* /*tz*/){
    if (!tv) return -22;
    linux_timeval* t = (linux_timeval*)tv;
    uint64_t ticks = pit_ticks;
    uint32_t freq = pit_frequency ? pit_frequency : 1000;
    t->tv_sec = (long)(ticks / freq);
    uint64_t rem = ticks % freq;
    t->tv_usec = (long)((rem * 1000000ULL) / freq);
    return 0;
}

// clock_gettime(2)
struct linux_timespec { long tv_sec; long tv_nsec; };

static long sys_clock_gettime(int /*clockid*/, void* ts){
    if (!ts) return -22;
    linux_timespec* t = (linux_timespec*)ts;
    uint64_t ticks = pit_ticks;
    uint32_t freq = pit_frequency ? pit_frequency : 1000;
    t->tv_sec = (long)(ticks / freq);
    uint64_t rem = ticks % freq;
    t->tv_nsec = (long)((rem * 1000000000ULL) / freq);
    return 0;
}

// nanosleep(2)
static long sys_nanosleep(const void* req, void* /*rem*/){
    if (!req) return -22;
    const linux_timespec* r = (const linux_timespec*)req;
    if (r->tv_sec < 0 || r->tv_nsec < 0) return -22;
    uint64_t ms = (uint64_t)r->tv_sec * 1000ULL + (uint64_t)r->tv_nsec / 1000000ULL;
    if (ms == 0 && r->tv_nsec > 0) ms = 1; // минимальная гранулярность
    thread_sleep((uint32_t)ms);
    return 0;
}

// --- Simple memory management for Linux ABI ---
static uint64_t user_brk_base = 0;
static uint64_t user_brk_end  = 0;
static uint64_t mmap_next     = 0x40000000ULL; // 1GB: выше зон ELF (0x20000000) и стека (0x30000000)

static void map_user_pages(uint64_t va_start, uint64_t size){
    uint64_t va = va_start & ~0xFFFULL;
    uint64_t va_end = (va_start + size + 0xFFFULL) & ~0xFFFULL;
    for (; va < va_end; va += 0x1000ULL){
        void* raw = kmalloc(0x2000);
        if (!raw) break;
        uint64_t phys = ((uint64_t)raw + 0xFFFULL) & ~0xFFFULL;
        paging_map_page(va, phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
        memset((void*)va, 0, 0x1000);
    }
}

static long sys_brk_impl(uint64_t newbrk){
    extern uint64_t elf_last_brk_base;
    if (user_brk_base == 0 && elf_last_brk_base) {
        user_brk_base = elf_last_brk_base;
        // Сразу выделим начальный пул кучи (256 КБ), чтобы malloc не упирался в пустоту
        uint64_t initial = 0x40000ULL; // 256KB
        map_user_pages(user_brk_base, initial);
        user_brk_end  = (user_brk_base + initial + 0xFFFULL) & ~0xFFFULL;
    } else if (user_brk_base == 0 && !elf_last_brk_base) {
        // Резервная база кучи, если ELF не сообщил конец PT_LOAD
        user_brk_base = 0x30000000ULL;
        user_brk_end  = user_brk_base;
        // начально промапим 64 КБ, чтобы malloc сразу получил валидную область
        map_user_pages(user_brk_base, 0x10000);
        user_brk_end = user_brk_base + 0x10000ULL;
    }
    if (newbrk == 0) {
        PrintfQEMU("[brk] query: base=0x%llx end=0x%llx -> ret=0x%llx\n",
                   (unsigned long long)user_brk_base,
                   (unsigned long long)user_brk_end,
                   (unsigned long long)user_brk_end);
        return (long)user_brk_end; // сообщаем текущий brk
    }
    if (newbrk < user_brk_base) return (long)user_brk_end; // сжатие пока игнорируем
    if (newbrk > user_brk_end){
        // выровняем вверх до страниц
        uint64_t prev_end = user_brk_end;
        uint64_t need_end = (newbrk + 0xFFFULL) & ~0xFFFULL;
        // запас 1 МБ, чтобы избежать частых расширений
        uint64_t slack = 0x100000ULL;
        uint64_t target_end = need_end + slack;
        if (target_end < need_end) target_end = need_end; // защититься от переполнения
        if (target_end > prev_end) {
            map_user_pages(prev_end, target_end - prev_end);
        }
        user_brk_end = target_end;
        PrintfQEMU("[brk] grow: prev_end=0x%llx need_end=0x%llx target_end=0x%llx (map %llu KB)\n",
                   (unsigned long long)prev_end,
                   (unsigned long long)need_end,
                   (unsigned long long)target_end,
                   (unsigned long long)((target_end - prev_end)/1024ULL));
    }
    PrintfQEMU("[brk] base=0x%llx end=0x%llx req=0x%llx -> ret=0x%llx\n",
               (unsigned long long)user_brk_base,
               (unsigned long long)user_brk_end,
               (unsigned long long)newbrk,
               (unsigned long long)newbrk);
    return (long)newbrk;
}

static uint64_t sys_mmap_impl(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t /*fd*/, uint64_t /*off*/){
    const uint64_t MAP_PRIVATE   = 0x02;
    const uint64_t MAP_ANONYMOUS = 0x20;
    const uint64_t MAP_FIXED     = 0x10;
    if (!(flags & MAP_ANONYMOUS)) return (uint64_t)-38; // only anonymous
    if (!(flags & MAP_PRIVATE)) return (uint64_t)-38;
    if (len == 0) return (uint64_t)-22;
    uint64_t size = (len + 0xFFFULL) & ~0xFFFULL;
    uint64_t base;
    if (flags & MAP_FIXED) {
        base = addr & ~0xFFFULL;
    } else {
        // Игнорируем предложенный addr, выбираем следующее свободное окно
        base = (mmap_next + 0xFFFULL) & ~0xFFFULL;
        mmap_next = base + size;
    }
    map_user_pages(base, size);
    (void)prot; // ignore for now
    PrintfQEMU("[mmap] addr=0x%llx len=0x%llx prot=0x%llx flags=0x%llx -> base=0x%llx size=0x%llx\n",
               (unsigned long long)addr, (unsigned long long)len,
               (unsigned long long)prot, (unsigned long long)flags,
               (unsigned long long)base, (unsigned long long)size);
    return base;
}

static uint64_t sys_mremap_impl(uint64_t old_addr, uint64_t old_len, uint64_t new_len, uint64_t flags, uint64_t new_addr){
    // Linux flags: MREMAP_MAYMOVE=1, MREMAP_FIXED=2. Мы поддержим MAYMOVE, игнорируем FIXED.
    const uint64_t MREMAP_MAYMOVE = 1;
    const uint64_t MREMAP_FIXED   = 2;
    if (new_len == 0) return (uint64_t)-22; // -EINVAL
    uint64_t old_size = (old_len + 0xFFFULL) & ~0xFFFULL;
    uint64_t new_size = (new_len + 0xFFFULL) & ~0xFFFULL;
    // Сжатие: просто оставляем старую мапу и возвращаем старый адрес
    if (new_size <= old_size) {
        PrintfQEMU("[mremap] shrink old=0x%llx old_len=0x%llx -> keep same\n",
                   (unsigned long long)old_addr, (unsigned long long)old_len);
        return old_addr;
    }
    // Расширение без MAYMOVE запрещаем
    if (!(flags & MREMAP_MAYMOVE)) return (uint64_t)-12; // -ENOMEM (как будто нельзя расширить на месте)
    // Если FIXED запрошен — попробуем по адресу new_addr, иначе создадим новую область
    uint64_t target = 0;
    if (flags & MREMAP_FIXED) {
        target = sys_mmap_impl(new_addr, new_size, /*prot*/3, /*flags*/0x02|0x20|0x10, /*fd*/0, /*off*/0);
        if ((int64_t)target < 0) return target;
    } else {
        target = sys_mmap_impl(0, new_size, /*prot*/3, /*flags*/0x02|0x20, /*fd*/0, /*off*/0);
        if ((int64_t)target < 0) return target;
    }
    // Скопируем данные
    uint64_t to_copy = (old_size < new_size) ? old_size : new_size;
    memcpy((void*)target, (const void*)old_addr, (size_t)to_copy);
    // Теоретически можно вызвать munmap на старой области; наш sys_munmap заглушка — игнорируем
    PrintfQEMU("[mremap] move old=0x%llx old_len=0x%llx -> new=0x%llx new_len=0x%llx\n",
               (unsigned long long)old_addr, (unsigned long long)old_len,
               (unsigned long long)target, (unsigned long long)new_len);
    return target;
}

static long sys_mprotect_impl(uint64_t /*addr*/, uint64_t /*len*/, uint64_t /*prot*/){
    return 0; // ignore for now
}

static long sys_munmap_impl(uint64_t /*addr*/, uint64_t /*len*/){
    return 0; // ignore for now (leak)
}

// madvise(2) заглушка
static long sys_madvise(uint64_t /*addr*/, uint64_t /*len*/, int /*advice*/){ return 0; }

extern "C" uint64_t sys_execve(const char* path, const char* const* argv, const char* const* envp){
    if (!path) return (uint64_t)-22; // -EINVAL
    // Copy path to kernel buffer
    size_t path_len = strlen(path);
    char* kpath = (char*)kmalloc(path_len + 1);
    if (!kpath) return (uint64_t)-12; // -ENOMEM
    memcpy(kpath, path, path_len + 1);

    // Copy argv/envp pointers and strings to kernel temp buffers
    const int MAX_ARGS = 64;
    const int MAX_ENVS = 64;
    const char* kargv_strs[MAX_ARGS]; size_t kargv_lens[MAX_ARGS]; int argc = 0;
    const char* kenv_strs[MAX_ENVS];  size_t kenv_lens[MAX_ENVS];  int envc = 0;
    if (argv){
        while (argc < MAX_ARGS && argv[argc]){
            const char* a = argv[argc]; size_t alen = strlen(a);
            char* astr = (char*)kmalloc(alen + 1); if (!astr) { argc = 0; break; }
            memcpy(astr, a, alen + 1);
            kargv_strs[argc] = astr; kargv_lens[argc] = alen + 1; argc++;
        }
    }
    if (envp){
        while (envc < MAX_ENVS && envp[envc]){
            const char* e = envp[envc]; size_t elen = strlen(e);
            char* estr = (char*)kmalloc(elen + 1); if (!estr) { envc = 0; break; }
            memcpy(estr, e, elen + 1);
            kenv_strs[envc] = estr; kenv_lens[envc] = elen + 1; envc++;
        }
    }
    if (envc == 0){
        // Default environment for interactive shells
        const char* def0 = "PATH=/bin:/usr/bin";
        const char* def1 = "HOME=/root";
        const char* def2 = "TERM=linux";
        const char* def3 = "PS1=$ ";
        kenv_strs[envc] = def0; kenv_lens[envc++] = strlen(def0) + 1;
        kenv_strs[envc] = def1; kenv_lens[envc++] = strlen(def1) + 1;
        kenv_strs[envc] = def2; kenv_lens[envc++] = strlen(def2) + 1;
        kenv_strs[envc] = def3; kenv_lens[envc++] = strlen(def3) + 1;
    }

    // Load ELF: map segments and user stack
    uint64_t entry = 0, ustack_top = 0;
    if (elf64_load_process(kpath, 1<<20, &entry, &ustack_top) != 0){
        kfree(kpath);
        return (uint64_t)-2ll; // -ENOENT
    }
    kfree(kpath);

    // Build user stack: [argc][argv*][NULL][envp*][NULL][auxv][...strings...]
    uint64_t sp = ustack_top;

    // Copy strings to top descending: argv then envp
    uint64_t arg_addrs[MAX_ARGS];
    for (int i = argc - 1; i >= 0; --i){ size_t len = kargv_lens[i]; sp -= len; memcpy((void*)sp, kargv_strs[i], len); arg_addrs[i] = sp; }
    uint64_t env_addrs[MAX_ENVS];
    for (int i = envc - 1; i >= 0; --i){ size_t len = kenv_lens[i]; sp -= len; memcpy((void*)sp, kenv_strs[i], len); env_addrs[i] = sp; }

    // Align to 16
    sp &= ~0xFULL;

    // Reserve vector space
    const int AUX_COUNT = 4; // AT_PAGESZ, AT_CLKTCK, AT_NULL x2 end pairs
    size_t vec_qwords = 1 + (size_t)argc + 1 + (size_t)envc + 1 + (size_t)(2*AUX_COUNT);
    sp -= vec_qwords * 8ULL;
    uint64_t* vec = (uint64_t*)sp;
    size_t idx = 0;
    vec[idx++] = (uint64_t)argc;
    for (int i = 0; i < argc; ++i) vec[idx++] = arg_addrs[i];
    vec[idx++] = 0; // argv NULL
    for (int i = 0; i < envc; ++i) vec[idx++] = env_addrs[i];
    vec[idx++] = 0; // envp NULL
    // auxv
    const uint64_t AT_NULL=0, AT_PAGESZ=6, AT_CLKTCK=17;
    vec[idx++] = AT_PAGESZ; vec[idx++] = 4096;
    vec[idx++] = AT_CLKTCK; vec[idx++] = 100;
    vec[idx++] = AT_NULL;   vec[idx++] = 0;
    vec[idx++] = AT_NULL;   vec[idx++] = 0;

    // Ensure SysV AMD64 ABI stack alignment at entry: RSP % 16 == 8
    if ((sp & 0xFULL) == 0) {
        sp -= 8ULL;
    }

    exec_new_rip = entry;
    exec_new_rsp = sp;
    exec_trampoline = 1;
    return 0;
}

// arch_prctl for x86_64: support ARCH_SET_FS (0x1002) and ARCH_GET_FS (0x1003)
static long sys_arch_prctl(long code, uint64_t addr){
    const long ARCH_SET_FS = 0x1002;
    const long ARCH_GET_FS = 0x1003;
    if (code == ARCH_SET_FS){
        // Опционально промапим область вокруг addr (если уже маплена, безвредно)
        uint64_t map_start = addr & ~0xFFFULL;
        uint64_t map_size  = 0x2000ULL;
        extern void map_user_pages(uint64_t va_start, uint64_t size);
        map_user_pages(map_start, map_size);
        PrintfQEMU("[arch_prctl] ARCH_SET_FS = 0x%llx (map hint 0x%llx-0x%llx)\n",
                   (unsigned long long)addr,
                   (unsigned long long)map_start,
                   (unsigned long long)(map_start + map_size));
        // Минимальный TCB: FS:0 должно указывать само на себя
        if (addr) {
            uint64_t* tcb = (uint64_t*)(uint64_t)addr;
            tcb[0] = addr; // self
        }
        // Установим FS base через WRMSR (IA32_FS_BASE)
        const uint32_t IA32_FS_BASE = 0xC0000100;
        uint32_t lo = (uint32_t)(addr & 0xFFFFFFFFu);
        uint32_t hi = (uint32_t)(addr >> 32);
        asm volatile("wrmsr" :: "c"(IA32_FS_BASE), "a"(lo), "d"(hi));
        PrintfQEMU("[arch_prctl] \"wrmsr\" :: \"c\"(IA32_FS_BASE), \"a\"(lo), \"d\"(hi) done\n");
        thread_t* t = thread_get_current_user();
        if (t) t->user_fs_base = addr;
        return 0;
    } else if (code == ARCH_GET_FS){
        thread_t* t = thread_get_current_user();
        if (!t) return -14; // -EFAULT
        uint64_t* p = (uint64_t*)addr;
        if (!p) return -14;
        *p = t->user_fs_base;
        return 0;
    }
    return -38; // -ENOSYS for others
}

static long sys_set_tid_address(uint64_t tidptr){
    // thread_t* t = thread_current();
    // if (t) {
    //     t->clear_child_tid = tidptr;
    //     return (long)t->tid;
    // }
    return 1;
}

static long sys_futex(uint64_t /*uaddr*/, int /*op*/, uint64_t /*val*/, uint64_t /*timeout*/, uint64_t /*uaddr2*/, uint64_t /*val3*/){
    // Однопоточный заглушечный вариант: «все ок»
    return 0;
}

static uint32_t g_umask = 0022;

static long sys_access(const char* path, int /*mode*/){
    if (!path) return -22; // -EINVAL
    if (strcmp(path, "/dev/tty") == 0) return 0;
    fs_stat_t st;
    return (fs_stat(path, &st) == 0) ? 0 : -2; // -ENOENT
}

static long sys_faccessat(int dirfd, const char* path, int mode, int /*flags*/){
    const int AT_FDCWD = -100;
    if (!path) return -22;
    if (dirfd != AT_FDCWD && path[0] != '/') return -9; // -EBADF/unsupported
    return sys_access(path, mode);
}

static long sys_readlink(const char* /*path*/, char* /*buf*/, unsigned long /*bufsz*/){
    return -2; // -ENOENT (no symlinks yet)
}

static long sys_unlink(const char* /*path*/){ return -30; } // -EROFS
static long sys_mkdir(const char* /*path*/, int /*mode*/){ return -30; } // -EROFS
static long sys_rmdir(const char* /*path*/){ return -30; } // -EROFS
static long sys_rename(const char* /*oldp*/, const char* /*newp*/){ return -30; } // -EROFS
static long sys_truncate(const char* /*path*/, long /*length*/){ return 0; }
static long sys_ftruncate(int /*fd*/, unsigned long /*length*/){ return 0; }
static long sys_ioctl(int fd, unsigned int cmd, unsigned long arg){
    PrintfQEMU("[ioctl] fd=%d cmd=0x%x arg=0x%llx\n", fd, cmd, (unsigned long long)arg);
    thread_t* t = active_thread();
    if (fd < 0 || fd >= THREAD_MAX_FD || !t->fds[fd]) return -9; // -EBADF
    if (is_tty_file(t->fds[fd])){
        if (cmd == LINUX_TCGETS) {
            struct termios_linux { unsigned int iflag, oflag, cflag, lflag; unsigned char line; unsigned char cc[32]; unsigned int ispeed, ospeed; };
            termios_linux* p = (termios_linux*)(uint64_t)arg;
            if (!p) return -14; // -EFAULT
            memset(p, 0, sizeof(*p));
            return 0;
        }
        if (cmd == LINUX_TIOCGWINSZ){
            struct winsz { unsigned short rows, cols, xpixel, ypixel; };
            winsz* w = (winsz*)(uint64_t)arg;
            if (!w) return -14;
            w->rows = 25; w->cols = 80; w->xpixel = 640; w->ypixel = 480;
            return 0;
        }
        return -25; // -ENOTTY for unsupported tty ioctls
    }
    if (cmd == LINUX_TCGETS) {
        struct termios_linux { unsigned int iflag, oflag, cflag, lflag; unsigned char line; unsigned char cc[32]; unsigned int ispeed, ospeed; };
        termios_linux* p = (termios_linux*)(uint64_t)arg;
        if (!p) return -14; // -EFAULT
        memset(p, 0, sizeof(*p));
        return 0;
    }
    if (cmd == LINUX_TIOCGWINSZ){
        struct winsz { unsigned short rows, cols, xpixel, ypixel; };
        winsz* w = (winsz*)(uint64_t)arg;
        if (!w) return -14;
        w->rows = 25; w->cols = 80; w->xpixel = 640; w->ypixel = 480;
        return 0;
    }
    return 0;
}

static long sys_umask(int mode){
    int old = (int)g_umask; g_umask = (uint32_t)(mode & 0777); return old;
}
static long sys_getuid(){ return 0; }
static long sys_geteuid(){ return 0; }
static long sys_getgid(){ return 0; }
static long sys_getegid(){ return 0; }
static long sys_gettid(){ thread_t* t = thread_current(); return t ? (long)t->tid : 1; }

struct linux_rlimit { uint64_t rlim_cur; uint64_t rlim_max; };
static long sys_getrlimit(int /*resource*/, void* rlim_user){
    if (!rlim_user) return -22; // -EINVAL
    linux_rlimit* r = (linux_rlimit*)rlim_user;
    r->rlim_cur = ~0ULL; r->rlim_max = ~0ULL; // RLIM_INFINITY
    return 0;
}
static long sys_prlimit64(int /*pid*/, int /*resource*/, const void* /*new_limit*/, void* old_limit){
    if (old_limit) return sys_getrlimit(0, old_limit);
    return 0;
}
static long sys_set_robust_list(void* /*head*/, size_t /*len*/){ return 0; }
static long sys_prctl(long /*option*/, unsigned long /*arg2*/, unsigned long /*arg3*/, unsigned long /*arg4*/, unsigned long /*arg5*/){ return 0; }

extern "C" void syscall_dispatch(cpu_registers_t* regs) {
    uint64_t nr = regs->rax;
    switch (nr) {
        case SYS_READ:
            regs->rax = sys_read((int)regs->rdi, (void*)regs->rsi, regs->rdx); break;
        case SYS_WRITE:
            regs->rax = sys_write((int)regs->rdi, (const char*)regs->rsi, regs->rdx); break;
        case SYS_OPEN:
            regs->rax = sys_open((const char*)regs->rdi, (int)regs->rsi); break;
        case SYS_CLOSE:
            regs->rax = sys_close((int)regs->rdi); break;
        case SYS_SEEK:
            regs->rax = sys_seek((int)regs->rdi, (int)regs->rsi, (int)regs->rdx); break;
        case SYS_SLEEP:
            sys_sleep(regs->rdi); regs->rax=0; break;
        case SYS_YIELD:
            sys_yield(); regs->rax=0; break;
        case SYS_EXIT:
            sys_exit((int)regs->rdi); break;
        default:
            PrintfQEMU("syscall: unknown nr=%llu\n", (unsigned long long)nr);
            break;
    }
}

extern "C" void syscall_isr(cpu_registers_t* regs) {
    syscall_dispatch(regs);
}

void syscall_init() {
    idt_set_gate(0x80, isr_stub_table[0x80], 0x08, 0xEE); // present | DPL=3 | interrupt gate
    idt_set_handler(0x80, syscall_isr);
} 