#ifndef ATA_H
#define ATA_H

#include <stdint.h>

#define ATA_PRIMARY_BASE    0x1F0
#define ATA_SECONDARY_BASE  0x170
#define ATA_CONTROL_BASE    0x3F6

#define ATA_DATA        0x00
#define ATA_ERROR       0x01
#define ATA_FEATURES    0x01
#define ATA_SECTOR_COUNT 0x02
#define ATA_SECTOR_NUM  0x03
#define ATA_CYL_LOW     0x04
#define ATA_CYL_HIGH    0x05
#define ATA_DRIVE       0x06
#define ATA_STATUS      0x07
#define ATA_COMMAND     0x07

#define ATA_CMD_READ    0x20
#define ATA_CMD_WRITE   0x30
#define ATA_CMD_IDENTIFY 0xEC
#define ATA_CMD_READ_DMA 0xC8
#define ATA_CMD_WRITE_DMA 0xCA

#define ATA_SR_BSY      0x80
#define ATA_SR_DRDY     0x40
#define ATA_SR_DF       0x20
#define ATA_SR_DSC      0x10
#define ATA_SR_DRQ      0x08
#define ATA_SR_CORR     0x04
#define ATA_SR_IDX      0x02
#define ATA_SR_ERR      0x01

// DMA definitions
#define ATA_DMA_BASE    0x00
#define ATA_DMA_COMMAND 0x08
#define ATA_DMA_STATUS  0x10
#define ATA_DMA_PRDT    0x18

#define ATA_DMA_CMD_START   0x01
#define ATA_DMA_CMD_STOP    0x00
#define ATA_DMA_STATUS_ACTIVE 0x01
#define ATA_DMA_STATUS_ERROR  0x02

// Operation modes
typedef enum {
    ATA_MODE_PIO,
    ATA_MODE_DMA
} ata_mode_t;

// Operation status
typedef enum {
    ATA_OP_IDLE,
    ATA_OP_READING,
    ATA_OP_WRITING,
    ATA_OP_COMPLETED,
    ATA_OP_ERROR
} ata_op_status_t;

typedef struct {
    uint8_t present;
    uint8_t type;
    uint32_t sectors;
    uint32_t size;      
    char name[40];        
    char vendor[40];
    char serial[20];
    ata_mode_t mode;        // PIO or DMA
    ata_op_status_t status; // Current operation status
    uint8_t* dma_buffer;    // DMA buffer if available
    uint32_t dma_buffer_size;
} ata_drive_t;

// DMA PRDT (Physical Region Descriptor Table) entry
typedef struct {
    uint32_t buffer_phys;   // Physical address of buffer
    uint16_t byte_count;    // Number of bytes to transfer
    uint16_t reserved;      // Must be 0
} ata_prdt_entry_t;

void ata_init();
int ata_read_sector(uint8_t drive, uint32_t lba, uint8_t* buffer);
int ata_write_sector(uint8_t drive, uint32_t lba, uint8_t* buffer);
ata_drive_t* ata_get_drive(uint8_t drive);

// New async functions for better multitasking support
int ata_read_sector_async(uint8_t drive, uint32_t lba, uint8_t* buffer);
int ata_write_sector_async(uint8_t drive, uint32_t lba, uint8_t* buffer);
int ata_poll_status(uint8_t drive);
void ata_wait_completion(uint8_t drive);

// DMA support functions
int ata_init_dma(uint8_t drive);
int ata_read_sector_dma(uint8_t drive, uint32_t lba, uint8_t* buffer);
int ata_write_sector_dma(uint8_t drive, uint32_t lba, uint8_t* buffer);

#endif // ATA_H 