#include <syscall.h>
#include <thread.h>
#include <vbetty.h>
#include <debug.h>
#include <fs_interface.h>

static void sys_yield() { thread_yield(); }

static long sys_write(int fd, const char* buf, unsigned long len) {
    if (fd != 1 || !buf || len == 0) return -1;
    for (unsigned long i = 0; i < len; ++i) {
        vbetty_put_char(buf[i]);
    }
    return (long)len;
}

static void sys_exit(int code) {
    (void)code;
    thread_t* user = thread_get_current_user();
    if (user) {
        thread_stop((int)user->tid);
        thread_set_current_user(nullptr);
    } else {
        thread_stop(thread_current()->tid);
    }
    thread_yield();
}

static int alloc_fd(thread_t* t, fs_file_t* f){
    for(int i=0;i<THREAD_MAX_FD;i++) if(!t->fds[i]){ t->fds[i]=f; return i; }
    return -1;
}

static long sys_open(const char* path, int flags){
    if(!path) return -1;
    fs_file_t* f = fs_open(path, flags);
    if(!f) return -1;
    int fd = alloc_fd(thread_current(), f);
    if(fd<0){ fs_close(f); return -1; }
    return fd;
}

static long sys_read(int fd, void* buf, unsigned long len){
    thread_t* t = thread_current();
    if(fd<0 || fd>=THREAD_MAX_FD || !t->fds[fd] || !buf) return -1;
    return fs_read(t->fds[fd], buf, len);
}

static long sys_close(int fd){
    thread_t* t = thread_current();
    if(fd<0 || fd>=THREAD_MAX_FD || !t->fds[fd]) return -1;
    int r = fs_close(t->fds[fd]);
    t->fds[fd]=nullptr;
    return r;
}

static long sys_seek(int fd, int off, int whence){
    thread_t* t = thread_current();
    if(fd<0 || fd>=THREAD_MAX_FD || !t->fds[fd]) return -1;
    return fs_seek(t->fds[fd], off, whence);
}

static void sys_sleep(unsigned long ms){
    thread_sleep((uint32_t)ms);
}

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