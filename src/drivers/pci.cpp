#include <pci.h>
#include <debug.h>
#include <fs_interface.h>
#include <string.h>
#include <stdint.h>

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static inline uint32_t pci_config_address(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset){
        return (uint32_t)(0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)device << 11) | ((uint32_t)function << 8) | (offset & 0xFC));
}

static uint32_t pci_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset){
        uint32_t addr = pci_config_address(bus, device, function, offset);
        outl(PCI_CONFIG_ADDRESS, addr);
        return inl(PCI_CONFIG_DATA);
}

static uint16_t pci_read16(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset){
        uint32_t v = pci_read32(bus, device, function, offset & 0xFC);
        return (uint16_t)((v >> ((offset & 2) * 8)) & 0xFFFF);
}

static uint8_t pci_read8(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset){
        uint32_t v = pci_read32(bus, device, function, offset & 0xFC);
        return (uint8_t)((v >> ((offset & 3) * 8)) & 0xFF);
}

// Exported helpers (defined here for other drivers)
uint32_t pci_config_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset){
        return pci_read32(bus, device, function, offset);
}

uint16_t pci_config_read16(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset){
        return pci_read16(bus, device, function, offset);
}

uint8_t pci_config_read8(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset){
        return pci_read8(bus, device, function, offset);
}

static void publish_pci_device(const pci_device_info_t* info, int index){
        // Лог в dmesg стиле
        klog_printf("pci: %02x:%02x.%x vendor=%04x device=%04x class=%02x subclass=%02x prog_if=%02x header=%02x",
                    info->bus, info->device, info->function,
                    info->vendor_id, info->device_id,
                    info->class_code, info->subclass, info->prog_if,
                    info->header_type);

        // Создать узел /dev/pci/<index>
        vfs_dev_create_dir("/dev/pci");
        char path[64];
        char buf[128];
        // имя вида /dev/pci/000
        int n = index;
        path[0] = '\0';
        strcat(path, "/dev/pci/");
        char num[16];
        num[0]='\0';
        // простая десятичная запись индекса
        {
                char t[16]; int i=0; if (n==0) t[i++]='0'; else { int x=n; while (x>0){ t[i++] = (char)('0' + (x%10)); x/=10; } } int j=0; while(i>0){ num[j++]=t[--i]; } num[j]='\0';
        }
        strcat(path, num);
        // содержимое файла — строка с полями
        char* p = buf;
        // В buf помещаем краткое описание
        // bus:dev.fn vendor device class subclass prog_if
        // ограничим вывод, чтобы не выйти за буфер
        // простая сборка
        // Прим: qemu_log_printf доступен, но здесь собираем в память
        // Формат без сложного snprintf
        {
                // bus
                const char* hex = "0123456789abcdef";
                *p++='b';*p++='u';*p++='s';*p++='='; *p++=hex[(info->bus>>4)&0xF]; *p++=hex[info->bus&0xF]; *p++=' ';
                *p++='d';*p++='e';*p++='v';*p++='='; *p++=hex[(info->device>>4)&0xF]; *p++=hex[info->device&0xF]; *p++=' ';
                *p++='f';*p++='n';*p++='='; *p++=hex[info->function&0xF]; *p++=' ';
                *p++='v';*p++='i';*p++='d';*p++='='; *p++=hex[(info->vendor_id>>12)&0xF]; *p++=hex[(info->vendor_id>>8)&0xF]; *p++=hex[(info->vendor_id>>4)&0xF]; *p++=hex[(info->vendor_id)&0xF]; *p++=' ';
                *p++='d';*p++='i';*p++='d';*p++='='; *p++=hex[(info->device_id>>12)&0xF]; *p++=hex[(info->device_id>>8)&0xF]; *p++=hex[(info->device_id>>4)&0xF]; *p++=hex[(info->device_id)&0xF]; *p++=' ';
                *p++='c';*p++='l';*p++='s';*p++='='; *p++=hex[(info->class_code>>4)&0xF]; *p++=hex[(info->class_code)&0xF]; *p++=' ';
                *p++='s';*p++='u';*p++='b';*p++='='; *p++=hex[(info->subclass>>4)&0xF]; *p++=hex[(info->subclass)&0xF]; *p++=' ';
                *p++='p';*p++='i';*p++='f';*p++='='; *p++=hex[(info->prog_if>>4)&0xF]; *p++=hex[(info->prog_if)&0xF];
                *p++='\n';
        }
        vfs_dev_create_file(path, buf, (unsigned long)(p - buf));
}

static void scan_bus(){
        int index = 0;
        for (int bus = 0; bus < 256; ++bus){
                for (int dev = 0; dev < 32; ++dev){
                        uint16_t vendor = pci_read16((uint8_t)bus, (uint8_t)dev, 0, 0x00);
                        if (vendor == 0xFFFF) continue; // no device

                        uint8_t header = pci_read8((uint8_t)bus, (uint8_t)dev, 0, 0x0E);
                        int func_count = (header & 0x80) ? 8 : 1;
                        for (int fn = 0; fn < func_count; ++fn){
                                vendor = pci_read16((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x00);
                                if (vendor == 0xFFFF) continue;
                                uint16_t device = pci_read16((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x02);
                                uint8_t class_code = pci_read8((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x0B);
                                uint8_t subclass = pci_read8((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x0A);
                                uint8_t prog_if = pci_read8((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x09);
                                uint8_t header_type = pci_read8((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x0E);

                                pci_device_info_t info;
                                info.bus = (uint8_t)bus; info.device = (uint8_t)dev; info.function = (uint8_t)fn;
                                info.vendor_id = vendor; info.device_id = device;
                                info.class_code = class_code; info.subclass = subclass; info.prog_if = prog_if; info.header_type = header_type;
                                publish_pci_device(&info, index++);
                        }
                }
        }
}

void pci_init(void){
        // Создаём /dev/pci и сканируем шину в краткой критической секции, чтобы
        // исключить гонки с логгингом/потоками во время ранней инициализации
        // unsigned long flags; asm volatile("pushfq; pop %0; cli" : "=r"(flags) :: "memory");
        // vfs_dev_create_dir("/dev");
        // vfs_dev_create_dir("/dev/pci");
        // asm volatile("push %0; popfq" :: "r"(flags) : "memory", "cc");

        klog_printf("pci: Scanning buses...");
        scan_bus();
        klog_printf("pci: Scan done.");
}


