#ifndef THREAD_H
#define THREAD_H
#include <stdint.h>
#include <context.h>
#include <fs_interface.h>

typedef enum {
    THREAD_READY,
    THREAD_RUNNING,
    THREAD_BLOCKED,
    THREAD_TERMINATED,
    THREAD_SLEEPING
} thread_state_t;

#define THREAD_MAX_FD 16

typedef struct thread {
    context_t context;
    uint64_t kernel_stack; // user mode (ring 3)
    uint64_t user_stack;   // user mode (ring 3)
    uint64_t user_rip;     // user mode (ring 3)
    uint64_t user_fs_base; // TLS base for userspace
    uint8_t ring;          // user mode (ring 3)
    thread_state_t state;
    struct thread* next;
    uint64_t tid;
    char name[32];
    uint32_t sleep_until;  // Время пробуждения (в тиках таймера)
    uint64_t clear_child_tid; // для set_tid_address
    fs_file_t* fds[THREAD_MAX_FD];
} thread_t;

extern int init;

void thread_init();
thread_t* thread_create(void (*entry)(void), const char* name);
void thread_yield();
void thread_schedule();
thread_t* thread_current();
void thread_stop(int pid);
thread_t* thread_get(int pid);
int thread_get_pid(const char* name);
void thread_block(int pid);
void thread_unblock(int pid);
int thread_get_state(int pid);
int thread_get_count();
void thread_sleep(uint32_t ms);

// Регистрация пользовательского «потока» (процесса) для отображения в списке
thread_t* thread_register_user(uint64_t user_rip, uint64_t user_rsp, const char* name);

// Доступ к текущему пользовательскому потоку
thread_t* thread_get_current_user();
void thread_set_current_user(thread_t* t);

#endif // THREAD_H 