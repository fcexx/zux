#include <iothread.h>
#include <heap.h>
#include <debug.h>
#include <string.h>
#include <spinlock.h>
#include <ata.h>
#include <thread.h>

// I/O планировщик
static io_request_t* pending_queue = nullptr;
static io_request_t* completed_queue = nullptr;
static spinlock_t io_lock = {0};
static int request_count = 0;
static bool iothread_initialized = false;

// I/O поток
static thread_t* io_thread = nullptr;

// Объявления внутренних функций
static void io_worker_thread();
static void process_io_request(io_request_t* request);

// Инициализация I/O планировщика
void iothread_init() {
        if (iothread_initialized) {
                return;
        }
        
        // Инициализируем спинлок
        io_lock = {0};
        
        // Создаем I/O поток
        io_thread = thread_create(io_worker_thread, "io_worker");
        if (io_thread) {
                iothread_initialized = true;
        }
}

// Рабочий поток для обработки I/O
static void io_worker_thread() {
        while (true) {
                io_request_t* request = nullptr;
                
                acquire(&io_lock);
                if (pending_queue) {
                        request = pending_queue;
                        pending_queue = pending_queue->next;
                        if (request) request->next = nullptr;
                }
                release(&io_lock);
                
                if (request) {
                        process_io_request(request);
                        
                        acquire(&io_lock);
                        // push to head is fine for completed; consumer takes specific id
                        request->next = completed_queue;
                        completed_queue = request;
                        release(&io_lock);
                } else {
                        // Нет запросов - уступаем квант
                        thread_yield();
                }
        }
}

// Обработка I/O запроса
static void process_io_request(io_request_t* request) {
        int rc = -1;
        switch (request->type) {
                case IO_OP_READ:
                        if (request->device_id < 4) {
                                rc = ata_read_sector(request->device_id, request->offset, request->buffer);
                        }
                        break;
                case IO_OP_WRITE:
                        if (request->device_id < 4) {
                                rc = ata_write_sector(request->device_id, request->offset, request->buffer);
                        }
                        break;
                default:
                        rc = -1;
                        break;
        }
        // статус операции: 0 = успех, -1 = ошибка; считаем завершённой всегда
        request->status = (rc == 0) ? 1 : -1;
}

// Добавить I/O запрос в очередь (FIFO)
int iothread_schedule_request(io_op_type_t type, uint8_t device_id, uint32_t offset, uint8_t* buffer, uint32_t size) {
        if (!iothread_initialized) return -1;
        
        io_request_t* request = (io_request_t*)kmalloc(sizeof(io_request_t));
        if (!request) return -1;
        
        request->type = type;
        request->device_id = device_id;
        request->offset = offset;
        request->buffer = buffer;
        request->size = size;
        request->requesting_thread = thread_current();
        request->status = 0; // pending
        request->next = nullptr;
        
        acquire(&io_lock);
        request->id = ++request_count;
        // вставка в хвост для FIFO
        if (!pending_queue) {
        pending_queue = request;
        } else {
                io_request_t* tail = pending_queue;
                while (tail->next) tail = tail->next;
                tail->next = request;
        }
        int rid = request->id;
        release(&io_lock);
        
        return rid;
}

// Ждать завершения конкретной I/O операции по id
int iothread_wait_completion(int request_id) {
        if (!iothread_initialized || request_id <= 0) return -1;
        
        while (true) {
                acquire(&io_lock);
                io_request_t* request = completed_queue;
                io_request_t* prev = nullptr;
                
                while (request) {
                        if (request->id == request_id && request->status != 0) {
                                // удаляем из очереди завершённых
                                if (prev) prev->next = request->next;
                                else completed_queue = request->next;
                                int status = request->status;
                                kfree(request);
                                release(&io_lock);
                                return (status == 1) ? 0 : -1; // 0 успех, -1 ошибка
                        }
                        prev = request;
                        request = request->next;
                }
                release(&io_lock);
                
                // уступаем процессор, чтобы IO-поток поработал
                thread_yield();
        }
}

// Проверить число готовых операций
int iothread_check_completed() {
        if (!iothread_initialized) return 0;
        
        acquire(&io_lock);
        int count = 0;
        for (io_request_t* r = completed_queue; r; r = r->next) {
                if (r->status != 0) count++;
        }
        release(&io_lock);
        return count;
}

// Получить завершенную операцию (любую)
io_request_t* iothread_get_completed() {
        if (!iothread_initialized) return nullptr;
        
        acquire(&io_lock);
        io_request_t* request = completed_queue;
        io_request_t* prev = nullptr;
        
        while (request) {
                if (request->status != 0) {
                        if (prev) prev->next = request->next;
                        else completed_queue = request->next;
                        request->next = nullptr;
                        release(&io_lock);
                        return request;
                }
                prev = request;
                request = request->next;
        }
        release(&io_lock);
        return nullptr;
}