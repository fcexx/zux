#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pci_device_info {
        uint8_t bus;
        uint8_t device;
        uint8_t function;
        uint16_t vendor_id;
        uint16_t device_id;
        uint8_t class_code;
        uint8_t subclass;
        uint8_t prog_if;
        uint8_t header_type;
} pci_device_info_t;

// Инициализация PCI: сканирование шины, логирование устройств, публикация в /dev
void pci_init(void);

#ifdef __cplusplus
}
#endif


