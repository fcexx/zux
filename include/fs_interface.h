#ifndef FS_INTERFACE_H
#define FS_INTERFACE_H

#include <stdint.h>
#include <stddef.h>

// Режимы открытия файла
#define FS_OPEN_READ    0x01
#define FS_OPEN_WRITE   0x02
#define FS_OPEN_APPEND  0x04
#define FS_OPEN_CREATE  0x08
#define FS_OPEN_TRUNCATE 0x10

// Константы для fs_seek
#define FS_SEEK_SET     0
#define FS_SEEK_CUR     1
#define FS_SEEK_END     2

// Атрибуты файла
#define FS_ATTR_READ_ONLY  0x01
#define FS_ATTR_HIDDEN     0x02
#define FS_ATTR_SYSTEM     0x04
#define FS_ATTR_VOLUME     0x08
#define FS_ATTR_DIRECTORY  0x10
#define FS_ATTR_ARCHIVE    0x20

// Структура для информации о файле
typedef struct {
    uint64_t size;           // Размер файла
    uint32_t attributes;     // Атрибуты файла
    uint32_t create_time;    // Время создания
    uint32_t modify_time;    // Время изменения
    uint32_t access_time;    // Время доступа
} fs_stat_t;

// Структура для записи в директории
typedef struct {
    char name[256];          // Имя файла
    uint32_t attributes;     // Атрибуты файла
    uint64_t size;           // Размер файла
    uint32_t create_time;    // Время создания
    uint32_t modify_time;    // Время изменения
} fs_dirent_t;

// Структура файла
typedef struct fs_file {
    void* private_data;      // Приватные данные файловой системы
    uint64_t position;       // Текущая позиция в файле
    uint64_t size;           // Размер файла
    int mode;                // Режим открытия
} fs_file_t;

// Структура директории
typedef struct fs_dir {
    void* private_data;      // Приватные данные файловой системы
    char path[256];          // Путь к директории
} fs_dir_t;

// Интерфейс файловой системы
typedef struct {
    // Инициализация файловой системы
    int (*init)(void);
    
    // Операции с файлами
    fs_file_t* (*open)(const char* path, int mode);
    int (*close)(fs_file_t* file);
    int (*read)(fs_file_t* file, void* buffer, size_t size);
    int (*write)(fs_file_t* file, const void* buffer, size_t size);
    int (*seek)(fs_file_t* file, int offset, int whence);
    
    // Операции с директориями
    fs_dir_t* (*opendir)(const char* path);
    int (*readdir)(fs_dir_t* dir, fs_dirent_t* entry);
    int (*closedir)(fs_dir_t* dir);
    
    // Операции с файлами и директориями
    int (*stat)(const char* path, fs_stat_t* stat);
    int (*mkdir)(const char* path);
    int (*unlink)(const char* path);
    int (*rename)(const char* old_path, const char* new_path);
} fs_interface_t;

// Общие функции файловой системы
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

#endif // FS_INTERFACE_H 