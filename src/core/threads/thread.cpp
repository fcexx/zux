#include <thread.h>
#include <heap.h>
#include <debug.h>
#include <string.h>
#include <pit.h>
#include <vga.h>
#include <context.h>

#define MAX_THREADS 32
thread_t* threads[MAX_THREADS];
int thread_count = 0;
static thread_t* current = NULL;
static thread_t* current_user = NULL; // регистрируемый юзер-процесс
int init = 0;
static thread_t main_thread;


void thread_init() {
        memset(&main_thread, 0, sizeof(main_thread));
        main_thread.state = THREAD_RUNNING;
        main_thread.tid = 0;
        main_thread.sleep_until = 0;
        for (int i=0;i<THREAD_MAX_FD;i++) main_thread.fds[i]=nullptr;
        current = &main_thread;
        threads[0] = &main_thread;
        thread_count = 1;
        strncpy(main_thread.name, "idle", sizeof(main_thread.name));
        klog_printf("thread_init: idle thread created with pid %d\n", main_thread.tid);
        init = 1;
}

// для старта потока
static void thread_trampoline(void) {
        void (*entry)(void);
        __asm__ __volatile__("movq %%r12, %0" : "=r"(entry)); // entry = r12
        entry();
        
        // Поток завершился - помечаем как завершенный
        thread_t* self = thread_current();
        if (self) {
                self->state = THREAD_TERMINATED;
        }
        
        // Переключаемся на другой поток
        thread_yield();
        
        // На всякий случай - если что-то пошло не так
        for (;;) {
                asm volatile("hlt");
        }
}

thread_t* thread_create(void (*entry)(void), const char* name) {
        if (thread_count >= MAX_THREADS) return NULL;
        thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
        if (!t) return NULL;
        memset(t, 0, sizeof(thread_t));
        for (int i=0;i<THREAD_MAX_FD;i++) t->fds[i]=nullptr;
        t->kernel_stack = (uint64_t)kmalloc(8192 + 16) + 8192;
        uint64_t* stack = (uint64_t*)t->kernel_stack;
        // Ensure 16-byte alignment for the stack pointer before ret
        uint64_t sp = ((uint64_t)&stack[-1]) & ~0xFULL;
        *((uint64_t*)sp) = (uint64_t)thread_trampoline; // ret пойдёт на trampoline
        t->context.rsp = sp;
        t->context.r12 = (uint64_t)entry; // entry передаётся через r12
        t->context.rflags = 0x202;
        t->state = THREAD_READY;
        t->sleep_until = 0;
        t->tid = thread_count;
        strncpy(t->name, name, sizeof(t->name));
        threads[thread_count++] = t;
        return t;
}

thread_t* thread_register_user(uint64_t user_rip, uint64_t user_rsp, const char* name){
        if (thread_count >= MAX_THREADS) return NULL;
        // Sanity checks: reject clearly invalid user contexts (entry==0 or tiny stack)
        if (user_rip == 0 || user_rsp < 0x1000) {
                qemu_log_printf("[thread] refusing to register user thread with invalid rip=0x%llx rsp=0x%llx\n",
                               (unsigned long long)user_rip, (unsigned long long)user_rsp);
                return NULL;
        }
        thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
        if (!t) return NULL;
        memset(t, 0, sizeof(thread_t));
        for (int i=0;i<THREAD_MAX_FD;i++) t->fds[i]=nullptr;
        t->ring = 3;
        t->user_rip = user_rip;
        t->user_stack = user_rsp;
        t->state = THREAD_RUNNING; // уже выполняется как текущее user‑задача
        t->sleep_until = 0;
        t->tid = thread_count;
        strncpy(t->name, name ? name : "user", sizeof(t->name));
        threads[thread_count++] = t;
        current_user = t;
        return t;
}

thread_t* thread_current() {
        return current;
}

void thread_yield() {
        thread_schedule();
}

void thread_stop(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_TERMINATED) {
                        threads[i]->state = THREAD_TERMINATED;
                        return;
                }
        }
        klog_printf("thread %d not found or already terminated\n", pid);
}

void thread_block(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_BLOCKED) {
                        threads[i]->state = THREAD_BLOCKED;
                        return;
                }
        }
}

void thread_sleep(uint32_t ms) {
        if (ms == 0) return;
        
        current->sleep_until = pit_ticks + ms;
        current->state = THREAD_SLEEPING;
        thread_yield();
}

void thread_schedule() {
        // Сначала проверяем спящие потоки
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->state == THREAD_SLEEPING) {
                        if (pit_ticks >= threads[i]->sleep_until) {
                                threads[i]->state = THREAD_READY;
                        }
                }
        }
        
        int next = (current->tid + 1) % thread_count;
        for (int i = 0; i < thread_count; ++i) {
                int idx = (next + i) % thread_count;
                if (threads[idx] && threads[idx]->state == THREAD_READY && threads[idx]->state != THREAD_TERMINATED) {
                        thread_t* prev = current;
                        current = threads[idx];
                        current->state = THREAD_RUNNING;
                        if (prev->state != THREAD_SLEEPING && prev->state != THREAD_TERMINATED) {
                                prev->state = THREAD_READY;
                        }
                        context_switch(&prev->context, &current->context);
                        return;
                }
        }
        current = &main_thread;
        current->state = THREAD_RUNNING;
}

void thread_unblock(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state == THREAD_BLOCKED) {
                        threads[i]->state = THREAD_READY;
                        return;
                }
        }
}

// get thread info by pid
thread_t* thread_get(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid) {
                        return threads[i];
                }
        }
        return NULL;
}

int thread_get_pid(const char* name) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && strcmp(threads[i]->name, name) == 0) {
                        return threads[i]->tid;
                }
        }
        return -1;
}

int thread_get_state(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid) {
                        return threads[i]->state;
                }
        }
        return -1;
}

int thread_get_count() {
        return thread_count;
}

thread_t* thread_get_current_user(){ return current_user; }
void thread_set_current_user(thread_t* t){ current_user = t; }