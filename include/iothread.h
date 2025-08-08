#ifndef IOTHREAD_H
#define IOTHREAD_H

#include <stdint.h>
#include <thread.h>

// I/O операции
typedef enum {
    IO_OP_READ,
    IO_OP_WRITE
} io_op_type_t;

// I/O запрос
typedef struct io_request {
    io_op_type_t type;
    uint8_t device_id;
    uint32_t offset;
    uint8_t* buffer;
    uint32_t size;
    thread_t* requesting_thread;
    int id;                 // unique request id
    int status;             // 0 = pending, 1 = completed, -1 = error
    struct io_request* next;
} io_request_t;

// Инициализация I/O планировщика
void iothread_init();

// Добавить I/O запрос в очередь
int iothread_schedule_request(io_op_type_t type, uint8_t device_id, uint32_t offset, uint8_t* buffer, uint32_t size);

// Ждать завершения I/O операции
int iothread_wait_completion(int request_id);

// Проверить, есть ли готовые I/O операции
int iothread_check_completed();

// Получить завершенную операцию
io_request_t* iothread_get_completed();

#endif // IOTHREAD_H 