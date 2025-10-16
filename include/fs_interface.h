#ifndef FS_INTERFACE_H
#define FS_INTERFACE_H

#include <stdint.h>
#include <stddef.h>

// fs interface for kernel so the kernel can use different filesystems
// like vfs initrd or fat32 or etc

// file open modes
#define FS_OPEN_READ        0x01
#define FS_OPEN_WRITE   0x02
#define FS_OPEN_APPEND  0x04
#define FS_OPEN_CREATE  0x08
#define FS_OPEN_TRUNCATE 0x10

// constants for fs_seek
#define FS_SEEK_SET         0
#define FS_SEEK_CUR         1
#define FS_SEEK_END         2

// file attributes
#define FS_ATTR_READ_ONLY  0x01
#define FS_ATTR_HIDDEN         0x02
#define FS_ATTR_SYSTEM         0x04
#define FS_ATTR_VOLUME         0x08
#define FS_ATTR_DIRECTORY  0x10
#define FS_ATTR_ARCHIVE        0x20

// struct for file info
typedef struct {
        uint64_t size;                   // file size
        uint32_t attributes;         // file attributes
        uint32_t create_time;        // creation time
        uint32_t modify_time;        // modification time
        uint32_t access_time;        // access time
} fs_stat_t;

// struct for writing to directory
typedef struct {
        char name[256];                  // file name (256 uh ok)
        uint32_t attributes;         // file attributes
        uint64_t size;                   // file size
        uint32_t create_time;        // creation time
        uint32_t modify_time;        // modification time
} fs_dirent_t;

// struct for file
typedef struct fs_file {
        void* private_data;          // private data for filesystem
        uint64_t position;           // current position in file
        uint64_t size;                   // file size
        int mode;                                // open mode
} fs_file_t;

// struct for directory
typedef struct fs_dir {
        void* private_data;          // private data for filesystem
        char path[256];                  // path to directory
} fs_dir_t;

// filesystem interface
typedef struct {
        // initialize filesystem
        int (*init)(void);
        
        // file operations
        fs_file_t* (*open)(const char* path, int mode);
        int (*close)(fs_file_t* file);
        int (*read)(fs_file_t* file, void* buffer, size_t size);
        int (*write)(fs_file_t* file, const void* buffer, size_t size);
        int (*seek)(fs_file_t* file, int offset, int whence);
        
        // directory operations
        fs_dir_t* (*opendir)(const char* path);
        int (*readdir)(fs_dir_t* dir, fs_dirent_t* entry);
        int (*closedir)(fs_dir_t* dir);
        
        // file and directory operations
        int (*stat)(const char* path, fs_stat_t* stat);
        int (*mkdir)(const char* path);
        int (*unlink)(const char* path);
        int (*rename)(const char* old_path, const char* new_path);
} fs_interface_t;

// general filesystem functions
int fs_init(fs_interface_t* fs_interface);
fs_file_t* fs_open(const char* path, int mode);
int fs_close(fs_file_t* file);
int fs_read(fs_file_t* file, void* buffer, size_t size);
int fs_write(fs_file_t* file, const void* buffer, size_t size);
int fs_seek(fs_file_t* file, int offset, int whence);
int fs_stat(const char* path, fs_stat_t* stat);
fs_dir_t* fs_opendir(const char* path);
int fs_readdir(fs_dir_t* dir, fs_dirent_t* entry);
int fs_closedir(fs_dir_t* dir);
int fs_mkdir(const char* path);
int fs_unlink(const char* path);
int fs_rename(const char* old_path, const char* new_path);
bool fs_is_initialized();
fs_interface_t* fs_get_current();
void fs_set_current(fs_interface_t* newfs);

// vfs from cpio
#ifdef __cplusplus
extern "C" {
#endif
fs_interface_t* vfs_get_interface();
int vfs_mount_from_cpio(const void* data, unsigned long size);
#ifdef __cplusplus
}
#endif

#endif // FS_INTERFACE_H 