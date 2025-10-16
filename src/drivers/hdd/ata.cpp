#include <ata.h>
#include <debug.h>
#include <string.h>
#include <vbetty.h>
#include <idt.h>
#include <pic.h>
#include <thread.h>

static ata_drive_t drives[4];
static volatile int ata_irq_received = 0;

static void ata_handler(cpu_registers_t* regs) {
        ata_irq_received = 1;
        // Пробуждаем поток, который ждет завершения операции
        // Это позволит другим потокам работать во время I/O
}

static void ata_wait(uint16_t base) {
        uint8_t status; 
        uint32_t timeout = 200000; // faster fail on absent device
        do {
                status = inb(base + ATA_STATUS);
                if (status == 0xFF || status == 0x00) {
                        // Likely no device on this bus
                        break;
                }
                if(--timeout == 0) {
                        kprintf("atamgr: Timeout waiting for device\n");
                        break;
                }
                // Даем возможность прерываниям работать
                if (timeout % 1000 == 0) {
                        asm volatile("nop");
                }
        } while (status & ATA_SR_BSY);
}

static int ata_check_error(uint16_t base) {
        uint8_t status = inb(base + ATA_STATUS);
        if (status & ATA_SR_ERR) return -1;
        return 0;
}

static void ata_select_drive(uint16_t base, uint8_t drive) {
        uint8_t value = 0xE0 | (drive << 4);
        outb(base + ATA_DRIVE, value);
        ata_wait(base);
}

static int ata_init_drive(uint16_t base, uint8_t drive) {
        ata_select_drive(base, drive);
        
        outb(base + ATA_COMMAND, ATA_CMD_IDENTIFY);
        ata_wait(base);

        uint8_t status = inb(base + ATA_STATUS);
        if (status == 0xFF || status == 0x00) return -1; // no device
        uint32_t timeout = 200000; // faster timeout
        while ((status & ATA_SR_BSY) && (--timeout != 0)) {
                status = inb(base + ATA_STATUS);
        }
        if (timeout == 0) return -1;

        if (ata_check_error(base)) return -1;

        //Check if DRQ is set, indicating data is ready to be read
        timeout = 200000; // Reset timeout quicker
        while (!((status & ATA_SR_DRQ) || (status & ATA_SR_ERR)) && (--timeout != 0)) {
                status = inb(base + ATA_STATUS);
        }
        if (timeout == 0 || (status & ATA_SR_ERR)) return -1; // if DRQ not set or error occurred

        uint16_t buffer[256];
        for (int i = 0; i < 256; i++) {
                buffer[i] = inw(base + ATA_DATA);
        }

        drives[drive].present = 1;
        drives[drive].type = 1; // ATA
        drives[drive].sectors = *(uint32_t*)&buffer[60];
        drives[drive].size = drives[drive].sectors * 512;
        drives[drive].mode = ATA_MODE_PIO; // По умолчанию используем PIO
        drives[drive].status = ATA_OP_IDLE;
        drives[drive].dma_buffer = NULL;
        drives[drive].dma_buffer_size = 0;

        char model[41] = {0};
        for (int i = 0; i < 20; i++) {
                model[i*2] = (buffer[27+i] >> 8) & 0xFF; //high byte (first char)
                model[i*2+1] = buffer[27+i] & 0xFF;         //low byte (second char)
        }
        model[40] = 0;
        trim(model);
        strncpy(drives[drive].name, model, 40);
        drives[drive].name[40] = 0;

        char serial[21] = {0};
        for (int i = 0; i < 10; i++) {
                serial[i*2] = (buffer[10+i] >> 8) & 0xFF; //high byte (first char)
                serial[i*2+1] = buffer[10+i] & 0xFF;         //low byte (second char)
        }
        serial[20] = 0;
        trim(serial);
        strncpy(drives[drive].serial, serial, 20);
        drives[drive].serial[20] = 0;

        char vendor_name[41] = {0};
        int vi = 0;
        for (int i = 0; i < 40 && model[i] != '\0'; i++) {
                if (model[i] == ' ' || model[i] == '-') break;
                vendor_name[vi++] = model[i];
        }
        vendor_name[vi] = '\0';
        for (int i = vi - 1; i >= 0 && vendor_name[i] == ' '; i--) {
                vendor_name[i] = '\0';
        }

        strncpy(drives[drive].vendor, vendor_name, 40);
        drives[drive].vendor[40] = 0;

        return 0;
}

static void read_device_info(uint16_t base, char* model) {

        outb(base + ATA_COMMAND, ATA_CMD_IDENTIFY);
        ata_wait(base);
        
        if (ata_check_error(base)) {
                strcpy(model, "unknown model");
                return;
        }

        uint16_t buffer[256];
        for (int i = 0; i < 256; i++) {
                buffer[i] = inw(base + ATA_DATA);
        }

        // Правильный порядок байт для модели устройства
        for (int i = 0; i < 20; i++) {
                model[i*2] = (buffer[27+i] >> 8) & 0xFF; //high byte (first char)
                model[i*2+1] = buffer[27+i] & 0xFF;         //low byte (second char)
        }
        model[40] = '\0';
        trim(model);
}

static int ata_identify_device(uint16_t base, uint8_t drive, char* model) {
        outb(base + ATA_DRIVE, 0xA0 | (drive << 4));
        inb(base + ATA_STATUS);
        for (int i = 0; i < 1000; i++) {
                if (!(inb(base + ATA_STATUS) & 0x80)) break;
        }
        outb(base + ATA_COMMAND, 0xEC);
        uint8_t status = 0;
        for (int i = 0; i < 1000; i++) {
                status = inb(base + ATA_STATUS);
                if (!(status & 0x80) && (status & 0x08)) break;
        }
        if (!(status & 0x08)) return -1;

        uint16_t buffer[256];
        for (int i = 0; i < 256; i++) buffer[i] = inw(base + ATA_DATA);

        // Правильный порядок байт для модели устройства
        for (int i = 0; i < 20; i++) {
                model[i*2] = (buffer[27+i] >> 8) & 0xFF; //high byte (first char)
                model[i*2+1] = buffer[27+i] & 0xFF;         //low byte (second char)
        }
        model[40] = 0;
        trim(model);
        return 0;
}

void ata_init() {
        memset(drives, 0, sizeof(drives));
        idt_set_handler(46, ata_handler);
        idt_set_handler(47, ata_handler);
        if (ata_init_drive(ATA_PRIMARY_BASE, 0) == 0) {
                kprintf("atamgr: found ata %s, ven: %s, ser: %s, sec: %u\n", 
                        drives[0].name, drives[0].vendor, drives[0].serial, drives[0].sectors);
        }
        
        if (ata_init_drive(ATA_PRIMARY_BASE, 1) == 0) {
                kprintf("atamgr: found ata %s, ven: %s, sec: %u\n", 
                        drives[1].name, drives[1].vendor, drives[1].sectors);
        }
        
        if (ata_init_drive(ATA_SECONDARY_BASE, 0) == 0) {
                kprintf("atamgr: found ata %s, ven: %s, sec: %u\n", 
                        drives[2].name, drives[2].vendor, drives[2].sectors);
        }
        
        if (ata_init_drive(ATA_SECONDARY_BASE, 1) == 0) {
                kprintf("atamgr: found ata %s, ven: %s, sec: %u\n", 
                        drives[3].name, drives[3].vendor,  drives[3].sectors);
        }
        // После полной инициализации контроллера можно разрешить его IRQ
        pic_unmask_irq(14);
        pic_unmask_irq(15);
}

// Улучшенная версия чтения сектора с поддержкой асинхронности
int ata_read_sector(uint8_t drive, uint32_t lba, uint8_t* buffer) {
        if (drive >= 4 || !drives[drive].present) {
                PrintfQEMU("atamgr: error read: bad drive %u\n", drive);
                return -1;
        }
        
        uint16_t base = (drive < 2) ? ATA_PRIMARY_BASE : ATA_SECONDARY_BASE;
        uint8_t drive_num = drive % 2;

        ata_select_drive(base, drive_num);

        outb(base + ATA_SECTOR_COUNT, 1);
        outb(base + ATA_SECTOR_NUM, lba & 0xFF);
        outb(base + ATA_CYL_LOW, (lba >> 8) & 0xFF);
        outb(base + ATA_CYL_HIGH, (lba >> 16) & 0xFF);
        outb(base + ATA_DRIVE, 0xE0 | (drive_num << 4) | ((lba >> 24) & 0x0F));

        outb(base + ATA_COMMAND, ATA_CMD_READ);
        
        // Ждем готовности устройства
        uint8_t status;
        uint32_t timeout = 200000;
        do {
                status = inb(base + ATA_STATUS);
                if (--timeout == 0) {
                        PrintfQEMU("atamgr: error read: BSY timeout lba=%u status=0x%02x\n", lba, status);
                        return -1;
                }
        } while (status & ATA_SR_BSY);

        if (ata_check_error(base)) {
                PrintfQEMU("atamgr: error read: ERR after BSY clear lba=%u status=0x%02x\n", lba, status);
                return -1;
        }

        // Ждем готовности данных
        timeout = 200000;
        do {
                status = inb(base + ATA_STATUS);
                if (--timeout == 0) {
                        PrintfQEMU("atamgr: error read: DRQ timeout lba=%u status=0x%02x\n", lba, status);
                        return -1;
                }
        } while (!(status & ATA_SR_DRQ) && !(status & ATA_SR_ERR));

        if (status & ATA_SR_ERR) {
                PrintfQEMU("atamgr: error read: DRQ error lba=%u status=0x%02x\n", lba, status);
                return -1;
        }

        // Читаем данные
        for (int i = 0; i < 256; i++) {
                uint16_t data = inw(base + ATA_DATA);
                buffer[i*2] = data & 0xFF;
                buffer[i*2+1] = (data >> 8) & 0xFF;
        }

        return 0;
}

// Пример использования асинхронных операций для мультизадачности
void ata_demo_async_operations() {
        uint8_t buffer1[512], buffer2[512];
        
        // Запускаем две асинхронные операции чтения
        if (ata_read_sector_async(0, 0, buffer1) == 0) {
                kprintf("atamgr: Started async read of sector 0\n");
        }
        
        if (ata_read_sector_async(0, 1, buffer2) == 0) {
                kprintf("atamgr: Started async read of sector 1\n");
        }
        
        // Пока операции выполняются, можем делать другие вещи
        kprintf("atamgr: Operations started, doing other work...\n");
        
        // Ждем завершения первой операции
        ata_wait_completion(0);
        kprintf("atamgr: First operation completed\n");
        
        // Ждем завершения второй операции
        ata_wait_completion(0);
        kprintf("atamgr: Second operation completed\n");
}

int ata_write_sector(uint8_t drive, uint32_t lba, uint8_t* buffer) {
        if (drive >= 4 || !drives[drive].present) return -1;
        uint16_t base = (drive < 2) ? ATA_PRIMARY_BASE : ATA_SECONDARY_BASE;
        uint8_t head = drive % 2;
        ata_select_drive(base, head);
        outb(base + ATA_SECTOR_COUNT, 1);
        outb(base + ATA_SECTOR_NUM, lba & 0xFF);
        outb(base + ATA_CYL_LOW, (lba >> 8) & 0xFF);
        outb(base + ATA_CYL_HIGH, (lba >> 16) & 0xFF);
        outb(base + ATA_DRIVE, 0xE0 | (head << 4) | ((lba >> 24) & 0x0F));
        outb(base + ATA_COMMAND, ATA_CMD_WRITE);
        uint8_t status;
        uint32_t timeout = 200000;

        do { status = inb(base + ATA_STATUS); } while (((status & ATA_SR_BSY) || !(status & ATA_SR_DRQ)) && --timeout);

        if (timeout == 0 || (status & ATA_SR_ERR)) {
                return -1;
        }
        for (int i = 0; i < 256; i++) {
                uint16_t data = buffer[i*2] | (buffer[i*2+1] << 8);
                outw(base + ATA_DATA, data);
        }
        timeout = 200000;

        do { status = inb(base + ATA_STATUS); } while ((status & ATA_SR_BSY) && --timeout);
        if (timeout == 0 || (status & ATA_SR_ERR)) {
                return -1;
        }
        return 0;
}

ata_drive_t* ata_get_drive(uint8_t drive) {
        if (drive >= 4 || !drives[drive].present) return NULL;
        return &drives[drive];
} 

// Асинхронная версия чтения сектора
int ata_read_sector_async(uint8_t drive, uint32_t lba, uint8_t* buffer) {
        if (drive >= 4 || !drives[drive].present) {
                kprintf("atamgr: Drive %d not present\n", drive);
                return -1;
        }
        
        uint16_t base = (drive < 2) ? ATA_PRIMARY_BASE : ATA_SECONDARY_BASE;
        uint8_t drive_num = drive % 2;

        ata_select_drive(base, drive_num);

        outb(base + ATA_SECTOR_COUNT, 1);
        outb(base + ATA_SECTOR_NUM, lba & 0xFF);
        outb(base + ATA_CYL_LOW, (lba >> 8) & 0xFF);
        outb(base + ATA_CYL_HIGH, (lba >> 16) & 0xFF);
        outb(base + ATA_DRIVE, 0xE0 | (drive_num << 4) | ((lba >> 24) & 0x0F));

        outb(base + ATA_COMMAND, ATA_CMD_READ);
        
        // Сохраняем буфер для последующего чтения
        drives[drive].dma_buffer = buffer;
        drives[drive].dma_buffer_size = 512;
        drives[drive].status = ATA_OP_READING;
        return 0; // Операция запущена, но не завершена
}

// Асинхронная версия записи сектора
int ata_write_sector_async(uint8_t drive, uint32_t lba, uint8_t* buffer) {
        if (drive >= 4 || !drives[drive].present) return -1;
        
        uint16_t base = (drive < 2) ? ATA_PRIMARY_BASE : ATA_SECONDARY_BASE;
        uint8_t drive_num = drive % 2;
        
        ata_select_drive(base, drive_num);
        outb(base + ATA_SECTOR_COUNT, 1);
        outb(base + ATA_SECTOR_NUM, lba & 0xFF);
        outb(base + ATA_CYL_LOW, (lba >> 8) & 0xFF);
        outb(base + ATA_CYL_HIGH, (lba >> 16) & 0xFF);
        outb(base + ATA_DRIVE, 0xE0 | (drive_num << 4) | ((lba >> 24) & 0x0F));
        outb(base + ATA_COMMAND, ATA_CMD_WRITE);
        
        // Ждем готовности к записи
        uint8_t status;
        uint32_t timeout = 1000000;
        do {
                status = inb(base + ATA_STATUS);
                if (--timeout == 0) return -1;
        } while (!(status & ATA_SR_DRQ) && !(status & ATA_SR_ERR));
        
        if (status & ATA_SR_ERR) return -1;
        
        // Записываем данные
        for (int i = 0; i < 256; i++) {
                uint16_t data = buffer[i*2] | (buffer[i*2+1] << 8);
                outw(base + ATA_DATA, data);
        }
        
        drives[drive].status = ATA_OP_WRITING;
        return 0;
}

// Проверка статуса операции
int ata_poll_status(uint8_t drive) {
        if (drive >= 4 || !drives[drive].present) return -1;
        
        uint16_t base = (drive < 2) ? ATA_PRIMARY_BASE : ATA_SECONDARY_BASE;
        uint8_t status = inb(base + ATA_STATUS);
        
        if (status & ATA_SR_ERR) {
                drives[drive].status = ATA_OP_ERROR;
                return -1;
        }
        
        if (drives[drive].status == ATA_OP_READING && (status & ATA_SR_DRQ)) {
                // Данные готовы для чтения
                uint8_t* buffer = drives[drive].dma_buffer;
                if (buffer) {
                        for (int i = 0; i < 256; i++) {
                                uint16_t data = inw(base + ATA_DATA);
                                buffer[i*2] = data & 0xFF;
                                buffer[i*2+1] = (data >> 8) & 0xFF;
                        }
                }
                
                drives[drive].status = ATA_OP_COMPLETED;
                return 0;
        }
        
        if (drives[drive].status == ATA_OP_WRITING && !(status & ATA_SR_BSY)) {
                drives[drive].status = ATA_OP_COMPLETED;
                return 0;
        }
        
        return 1; // Операция еще выполняется
}

// Ожидание завершения операции с возможностью переключения потоков
void ata_wait_completion(uint8_t drive) {
        uint32_t timeout = 1000000; // Таймаут для предотвращения бесконечного цикла
        while (ata_poll_status(drive) == 1 && --timeout > 0) {
                // Переключаемся на другой поток, пока ждем
                thread_yield();
        }
        
        if (timeout == 0) {
                kprintf("atamgr: Timeout waiting for completion on drive %d\n", drive);
                drives[drive].status = ATA_OP_ERROR;
        }
} 