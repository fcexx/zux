// Новый заголовочный файл FAT32
#ifndef FAT32_H
#define FAT32_H

#include <stdint.h>
#include <fs_interface.h>

// oh, fuck.

// BPB for fat32
#pragma pack(push, 1)
typedef struct {
        uint8_t  jump_boot[3];  // jump to boot
        uint8_t  oem_name[8];
        uint16_t bytes_per_sector;
        uint8_t  sectors_per_cluster;
        uint16_t reserved_sector_count;
        uint8_t  table_count;
        uint16_t root_entry_count;
        uint16_t total_sectors_16;
        uint8_t  media_type;
        uint16_t table_size_16;
        uint16_t sectors_per_track;
        uint16_t head_side_count;
        uint32_t hidden_sector_count;
        uint32_t total_sectors_32;
        // fat32 extended
        uint32_t table_size_32;
        uint16_t ext_flags;
        uint16_t fat_version;
        uint32_t root_cluster;
        uint16_t fat_info;
        uint16_t backup_BS_sector;
        uint8_t  reserved_0[12];
        uint8_t  drive_number;
        uint8_t  reserved_1;
        uint8_t  boot_signature; // yeah second signature
        uint32_t volume_id;
        uint8_t  volume_label[11]; // volume label like (ur mom's pussy pc)
        uint8_t  fat_type_label[8];
} fat32_bpb_t;
#pragma pack(pop)

// Standard 8.3 directory entry (-9999 social credit)
#pragma pack(push, 1)
typedef struct {
        char         name[11]; // old fucking msdos shit
        uint8_t  attr;
        uint8_t  ntres;
        uint8_t  crt_time_tenth;
        uint16_t crt_time;
        uint16_t crt_date;
        uint16_t lst_acc_date;
        uint16_t first_cluster_high;
        uint16_t wrt_time;
        uint16_t wrt_date;
        uint16_t first_cluster_low;
        uint32_t file_size;
} fat32_dir_entry_t;
#pragma pack(pop)

// LFN entry (attribute 0x0F)
#pragma pack(push,1)
typedef struct {          // long name entry (+9999 social credit)
        uint8_t  order;                          // order number (bit 6 – LAST_LONG_ENTRY)
        uint16_t name1[5];
        uint8_t  attr;                           // 0x0F
        uint8_t  type;                           // always 0
        uint8_t  checksum;                   // checksum of short name
        uint16_t name2[6];
        uint16_t first_cluster_low;  // always 0
        uint16_t name3[2];
} fat32_lfn_entry_t;
#pragma pack(pop)

// extended struct for returning file info
#define FAT32_MAX_NAME 255

typedef struct {
        char         name[FAT32_MAX_NAME+1]; // full name (LFN or 8.3 msdos shit)
        uint8_t  attr;
        uint32_t first_cluster;
        uint32_t size;
} fat32_entry_t;

// public api for disk driver
#ifdef __cplusplus
extern "C" {
#endif

int          fat32_mount(uint8_t drive);
uint32_t fat32_cluster_to_lba(uint32_t cluster);
uint32_t fat32_get_next_cluster(uint8_t drive, uint32_t cluster);

// read directory with conversion of LFN chains. returns number of elements.
int fat32_list_dir(uint8_t drive, uint32_t cluster,
                                   fat32_entry_t* entries, int max_entries);

// backward compatibility - functions that were previously referenced by shell.c
int fat32_read_dir(uint8_t drive, uint32_t cluster,
                                   fat32_dir_entry_t* entries, int max_entries);
int fat32_read_file(uint8_t drive, uint32_t first_cluster,
                                        uint8_t* buf, uint32_t size);
int fat32_write_file(uint8_t drive, const char* path,
                                         const uint8_t* buf, uint32_t size);
int fat32_create_file(uint8_t drive, const char* path);
int fat32_write_file_data(uint8_t drive, const char* path,
                                                  const uint8_t* buf, uint32_t size,
                                                  uint32_t offset);
int fat32_read_file_data(uint8_t drive, const char* path,
                                                 uint8_t* buf, uint32_t size,
                                                 uint32_t offset);
int fat32_create_dir(uint8_t drive, const char* name);

int fat32_resolve_path(uint8_t drive, const char* path, uint32_t* target_cluster);
int fat32_change_dir(uint8_t drive, const char* path);

void fat32_create_fs(uint8_t drive);

// integration with fs_interface
fs_interface_t* fat32_get_interface(void);
int fat32_init(void);

extern fat32_bpb_t  fat32_bpb;
extern uint32_t         fat_start;
extern uint32_t         root_dir_first_cluster;
extern uint32_t         current_dir_cluster;

#ifdef __cplusplus
}
#endif

// i wanna suicide after this

#endif // FAT32_H 