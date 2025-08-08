#include <fs_interface.h>
#include <heap.h>
#include <string.h>
#include <vbetty.h>
#include <debug.h>

// Глобальные переменные для управления файловыми системами
static fs_interface_t current_fs = {0};
static bool fs_initialized = false;

// Инициализация файловой системы
int fs_init(fs_interface_t* fs_interface) {
    if (fs_initialized) {
        kprintf("FS: Already initialized\n");
        return -1;
    }
    
    if (!fs_interface || !fs_interface->init) {
        kprintf("FS: Invalid interface\n");
        return -1;
    }
    
    int result = fs_interface->init();
    if (result == 0) {
        // копируем таблицу функций локально, чтобы не зависеть от внешнего указателя
        memcpy(&current_fs, fs_interface, sizeof(fs_interface_t));
        fs_initialized = true;
        kprintf("FS: Initialized successfully\n");
    } else {
        kprintf("FS: Initialization failed\n");
    }
    
    PrintfQEMU("[fs] init -> %d\n", result);
    return result;
}

// Открытие файла
fs_file_t* fs_open(const char* path, int mode) {
    PrintfQEMU("[fs] open(path='%s', mode=0x%x)\n", path ? path : "<null>", mode);
    if (!fs_initialized || !current_fs.open) {
        kprintf("FS: Not initialized or no open function\n");
        return nullptr;
    }
    
    fs_file_t* f = current_fs.open(path, mode);
    PrintfQEMU("[fs] open -> %p\n", f);
    return f;
}

// Закрытие файла
int fs_close(fs_file_t* file) {
    PrintfQEMU("[fs] close(%p)\n", file);
    if (!fs_initialized || !current_fs.close) {
        return -1;
    }
    
    int r = current_fs.close(file);
    PrintfQEMU("[fs] close -> %d\n", r);
    return r;
}

// Чтение из файла
int fs_read(fs_file_t* file, void* buffer, size_t size) {
    PrintfQEMU("[fs] read(file=%p, buf=%p, size=%zu)\n", file, buffer, size);
    if (!fs_initialized || !current_fs.read) {
        return -1;
    }
    
    int r = current_fs.read(file, buffer, size);
    PrintfQEMU("[fs] read -> %d\n", r);
    return r;
}

// Запись в файл
int fs_write(fs_file_t* file, const void* buffer, size_t size) {
    PrintfQEMU("[fs] write(file=%p, buf=%p, size=%zu)\n", file, buffer, size);
    if (!fs_initialized || !current_fs.write) {
        return -1;
    }
    
    int r = current_fs.write(file, buffer, size);
    PrintfQEMU("[fs] write -> %d\n", r);
    return r;
}

// Поиск файла
int fs_seek(fs_file_t* file, int offset, int whence) {
    PrintfQEMU("[fs] seek(file=%p, offset=%d, whence=%d)\n", file, offset, whence);
    if (!fs_initialized || !current_fs.seek) {
        return -1;
    }
    PrintfQEMU("[fs] seek: tbl=%p, fn=%p, file->priv=%p size=%llu pos=%llu\n",
               &current_fs,
               current_fs.seek,
               file ? file->private_data : nullptr,
               (unsigned long long)(file ? file->size : 0ULL),
               (unsigned long long)(file ? file->position : 0ULL));
    int r = current_fs.seek(file, offset, whence);
    PrintfQEMU("[fs] seek -> %d\n", r);
    return r;
}

// Получение информации о файле
int fs_stat(const char* path, fs_stat_t* stat) {
    PrintfQEMU("[fs] stat(path='%s', stat=%p)\n", path ? path : "<null>", stat);
    if (!fs_initialized || !current_fs.stat) {
        return -1;
    }
    
    int r = current_fs.stat(path, stat);
    PrintfQEMU("[fs] stat -> %d\n", r);
    return r;
}

// Чтение директории
fs_dir_t* fs_opendir(const char* path) {
    PrintfQEMU("[fs] opendir(path='%s')\n", path ? path : "<null>");
    if (!fs_initialized || !current_fs.opendir) {
        return nullptr;
    }
    
    fs_dir_t* d = current_fs.opendir(path);
    PrintfQEMU("[fs] opendir -> %p\n", d);
    return d;
}

// Чтение следующей записи в директории
int fs_readdir(fs_dir_t* dir, fs_dirent_t* entry) {
    PrintfQEMU("[fs] readdir(dir=%p, entry=%p)\n", dir, entry);
    if (!fs_initialized || !current_fs.readdir) {
        return -1;
    }
    
    int r = current_fs.readdir(dir, entry);
    if (r == 0) {
        PrintfQEMU("[fs] readdir -> 0 name='%s' attr=0x%x size=%u\n", entry->name, entry->attributes, (unsigned)entry->size);
    } else {
        PrintfQEMU("[fs] readdir -> %d\n", r);
    }
    return r;
}

// Закрытие директории
int fs_closedir(fs_dir_t* dir) {
    PrintfQEMU("[fs] closedir(%p)\n", dir);
    if (!fs_initialized || !current_fs.closedir) {
        return -1;
    }
    
    int r = current_fs.closedir(dir);
    PrintfQEMU("[fs] closedir -> %d\n", r);
    return r;
}

// Создание директории
int fs_mkdir(const char* path) {
    PrintfQEMU("[fs] mkdir(path='%s')\n", path ? path : "<null>");
    if (!fs_initialized || !current_fs.mkdir) {
        return -1;
    }
    
    int r = current_fs.mkdir(path);
    PrintfQEMU("[fs] mkdir -> %d\n", r);
    return r;
}

// Удаление файла
int fs_unlink(const char* path) {
    PrintfQEMU("[fs] unlink(path='%s')\n", path ? path : "<null>");
    if (!fs_initialized || !current_fs.unlink) {
        return -1;
    }
    
    int r = current_fs.unlink(path);
    PrintfQEMU("[fs] unlink -> %d\n", r);
    return r;
}

// Переименование файла
int fs_rename(const char* old_path, const char* new_path) {
    PrintfQEMU("[fs] rename('%s' -> '%s')\n", old_path ? old_path : "<null>", new_path ? new_path : "<null>");
    if (!fs_initialized || !current_fs.rename) {
        return -1;
    }
    
    int r = current_fs.rename(old_path, new_path);
    PrintfQEMU("[fs] rename -> %d\n", r);
    return r;
}

// Проверка инициализации
bool fs_is_initialized() {
    return fs_initialized;
}

// Получение текущей файловой системы
fs_interface_t* fs_get_current() {
    return &current_fs;
}
