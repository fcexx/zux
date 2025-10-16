// from github
#include <fat32.h>
#include <ata.h>
#include <debug.h>
#include <string.h>
#include <heap.h>
#include <stdbool.h>
#include <stdint.h>
static_assert(sizeof(fat32_dir_entry_t)==32, "fat32_dir_entry_t must be 32 bytes");

#ifndef FAT_DEBUG
#define FAT_DEBUG 0
#endif

/* ---------------------------------------------------------------------
 *  Global variables, accessible to other modules
 * -------------------------------------------------------------------*/
fat32_bpb_t fat32_bpb;
uint32_t        fat_start                          = 0;
uint32_t        root_dir_first_cluster = 2;
uint32_t        current_dir_cluster        = 2;

/* private */
static uint32_t cluster_begin_lba   = 0;
static uint32_t sectors_per_fat         = 0;
static uint32_t total_clusters          = 0;
static uint32_t partition_lba           = 0;  // LBA начала раздела
/* Hint for fast search for free clusters */
static uint32_t next_free_hint          = 3;

/* Cache of one FAT sector for speeding up get_next_cluster */
static uint32_t cached_fat_sector   = 0xFFFFFFFF;
static uint8_t  fat_cache[512];

/* Forward declarations for helpers located later in this file */
static uint32_t find_free_cluster(uint8_t drive);
static int          fat_write_fat_entry(uint8_t drive, uint32_t cluster, uint32_t value);

// ------------------------------------------------------------------
static char toupper_ascii(char c) {
        return (c>='a' && c<='z') ? (c - ('a'-'A')) : c;
}

/* Decode 13 UTF-16 characters from LFN record to ASCII.
 * Returns the number of added characters. */
static int lfn_copy_part(char *dst, const fat32_lfn_entry_t *lfn) {
        if (!dst || !lfn) return 0;
        int pos = 0;
        const uint8_t *p = reinterpret_cast<const uint8_t*>(lfn);
        auto read_char = [&](int byte_off) -> uint8_t {
                // UTF-16LE: берём младший байт
                uint8_t lo = p[byte_off];
                uint8_t hi = p[byte_off+1];
                (void)hi; // игнорируем для ASCII
                return lo;
        };
        // name1: 5 UTF-16 (offset 1..10)
        for (int i = 0; i < 5; i++) {
                uint8_t ch = read_char(1 + i*2);
                if (ch==0x00 || ch==0xFF) { dst[pos]=0; return pos; }
                dst[pos++] = ch;
        }
        // name2: 6 UTF-16 (offset 14..25)
        for (int i = 0; i < 6; i++) {
                uint8_t ch = read_char(14 + i*2);
                if (ch==0x00 || ch==0xFF) { dst[pos]=0; return pos; }
                dst[pos++] = ch;
        }
        // name3: 2 UTF-16 (offset 28..31)
        for (int i = 0; i < 2; i++) {
                uint8_t ch = read_char(28 + i*2);
                if (ch==0x00 || ch==0xFF) { dst[pos]=0; return pos; }
                dst[pos++] = ch;
        }
        dst[pos]=0;
        return pos;
}

/* Comparison of ASCII strings without regard to case. */
static int strcasecmp_ascii(const char *a, const char *b) {
        while (*a && *b) {
                char ca = toupper_ascii(*a);
                char cb = toupper_ascii(*b);
                if (ca!=cb) return ca - cb;
                ++a; ++b;
        }
        return (*a) - (*b);
}

/* Подсчитать checksum короткого имени (для LFN). */
static uint8_t shortname_checksum(const char name[11]) {
        uint8_t sum = 0;
        for (int i=0;i<11;i++) {
                sum = ((sum>>1) | (sum<<7)) + (uint8_t)name[i];
        }
        return sum;
}

/* Преобразовать короткое имя в человекочитаемую строку (без пробелов). */
static void shortname_to_string(const char in[11], char *out) {
        int pos=0;
        /* имя */
        for (int i=0;i<8;i++) {
                if (in[i]==' ') break;
                out[pos++] = in[i];
        }
        /* расширение */
        int has_ext=0;
        for (int i=8;i<11;i++) if (in[i]!=' ') { has_ext=1; break; }
        if (has_ext) {
                out[pos++]='.';
                for (int i=8;i<11;i++) {
                        if (in[i]==' ') break;
                        out[pos++] = in[i];
                }
        }
        out[pos]=0;
}

/* ---------------------------------------------------------------------
 *                                                  НИЗКОУРОВНЕВЫЕ ФУНКЦИИ
 * -------------------------------------------------------------------*/
int fat32_mount(uint8_t drive) {
        uint8_t *sector = (uint8_t*)kmalloc(512);
        if (!sector) return -1;
        
        // Читаем MBR (сектор 0)
        if (ata_read_sector(drive, 0, sector)!=0) { kfree(sector); return -2; }
        
        // Проверяем сигнатуру MBR
        if (sector[0x1FE] != 0x55 || sector[0x1FF] != 0xAA) {
                kfree(sector); 
                PrintfQEMU("[FAT32][ERR] fat32_mount: invalid mbr signature (0x%02X%02X)\n", sector[0x1FE], sector[0x1FF]); 
                return -3;
        }
        
        // Ищем активный раздел FAT32
        partition_lba = 0;
        for (int i = 0; i < 4; i++) {
                int offset = 0x1BE + i * 16;
                uint8_t status = sector[offset];
                uint8_t type = sector[offset + 4];
                
                PrintfQEMU("[FAT32][INFO] fat32_mount: partition %d: status=0x%02X, type=0x%02X\n", i, status, type);
                
                // Проверяем что раздел имеет тип FAT32 (не обязательно активный)
                if (type == 0x0B || type == 0x0C) {
                        // Читаем LBA первого сектора раздела
                        partition_lba = *(uint32_t*)(&sector[offset + 8]);
                        PrintfQEMU("[FAT32][INFO] fat32_mount: found fat32 partition at LBA %u\n", partition_lba);
                        break;
                }
        }
        
        if (partition_lba == 0) {
                kfree(sector); 
                PrintfQEMU("[FAT32][ERR] fat32_mount: no fat32 partition found\n"); 
                return -4;
        }
        
        // Читаем загрузочный сектор раздела
        if (ata_read_sector(drive, partition_lba, sector)!=0) { kfree(sector); return -5; }
        
        // Проверяем сигнатуру загрузочного сектора
        if (sector[0x1FE] != 0x55 || sector[0x1FF] != 0xAA) {
                kfree(sector); 
                PrintfQEMU("[FAT32][ERR] fat32_mount: invalid boot sector signature\n"); 
                return -6;
        }
        
        memcpy(&fat32_bpb, sector, sizeof(fat32_bpb)); /* dst=bpb, src=sector */

        if (fat32_bpb.table_size_32==0) { kfree(sector); PrintfQEMU("[FAT32][ERR] fat32_mount: table_size_32 is 0\n"); return -7; }
        sectors_per_fat         = fat32_bpb.table_size_32;
        fat_start                   = fat32_bpb.reserved_sector_count;
        cluster_begin_lba   = fat_start + fat32_bpb.table_count * sectors_per_fat;
        root_dir_first_cluster = fat32_bpb.root_cluster ? fat32_bpb.root_cluster : 2;
        current_dir_cluster = root_dir_first_cluster;

        PrintfQEMU("[FAT32][INFO] fat32: sectors_per_fat: %u\n", sectors_per_fat);
        PrintfQEMU("[FAT32][INFO] fat32: fat_start: %u\n", fat_start);
        PrintfQEMU("[FAT32][INFO] fat32: cluster_begin_lba: %u\n", cluster_begin_lba);
        PrintfQEMU("[FAT32][INFO] fat32: root_dir_first_cluster: %u\n", root_dir_first_cluster);
        PrintfQEMU("[FAT32][INFO] fat32: current_dir_cluster: %u\n", current_dir_cluster);

        /* количество доступных кластеров на разделе */
        uint32_t data_sectors = fat32_bpb.total_sectors_32 - cluster_begin_lba;
        total_clusters = data_sectors / fat32_bpb.sectors_per_cluster;

        kfree(sector);
        cached_fat_sector = 0xFFFFFFFF; // сброс кеша
        next_free_hint        = 3;                  // сброс hint-указателя

        return 0;
}

uint32_t fat32_cluster_to_lba(uint32_t cluster) {
        return partition_lba + cluster_begin_lba + (cluster-2) * fat32_bpb.sectors_per_cluster;
}

uint32_t fat32_get_next_cluster(uint8_t drive, uint32_t cluster) {
        uint32_t fat_offset = cluster * 4;                           // 4 байта на запись
        uint32_t fat_sector = partition_lba + fat_start + (fat_offset / 512);
        uint32_t ent_offset = fat_offset % 512;

        if (fat_sector != cached_fat_sector) {
                if (ata_read_sector(drive, fat_sector, fat_cache)!=0)
                        return 0x0FFFFFFF; // ошибка
                cached_fat_sector = fat_sector;
        }
        uint32_t next = *(uint32_t*)(&fat_cache[ent_offset]) & 0x0FFFFFFF;
        return next;
}

/* ------------------------------------------------------------------
 *                        ЧТЕНИЕ КАТАЛОГА (с построением LFN)
 * ----------------------------------------------------------------*/
int fat32_list_dir(uint8_t drive, uint32_t cluster,
                                   fat32_entry_t* out, int max_entries) {
        PrintfQEMU("[FAT32] fat32_list_dir: cluster = %u, max_entries = %d\n", cluster, max_entries);
        uint8_t *sector = (uint8_t*)kmalloc(512);
        if (!sector) {
                PrintfQEMU("[FAT32] fat32_list_dir: kmalloc failed\n");
                return -1;
        }
        int count = 0;

        char lfn_parts[20][14]; // до 20 частей х 13 символов = 260
        int  lfn_present = 0;

        uint32_t cl = cluster;
        while (cl < 0x0FFFFFF8) {
                PrintfQEMU("[FAT32] fat32_list_dir: processing cluster %u\n", cl);
                for (uint8_t s=0; s<fat32_bpb.sectors_per_cluster; s++) {
                        uint32_t lba = fat32_cluster_to_lba(cl)+s;
                        PrintfQEMU("[FAT32] fat32_list_dir: reading sector %u\n", lba);
                        if (ata_read_sector(drive, lba, sector)!=0) { 
                                PrintfQEMU("[FAT32] fat32_list_dir: ata_read_sector failed\n");
                                kfree(sector); 
                                return -2; 
                        }

                        for (int off=0; off<512; off+=32) {
                                fat32_dir_entry_t *ent = (fat32_dir_entry_t*)&sector[off];
                                PrintfQEMU("[FAT32] fat32_list_dir: checking entry at offset %d, name[0]=0x%02x, attr=0x%02x\n", off, ent->name[0], ent->attr);
                                if (ent->name[0]==0x00) { 
                                        // Это пустая запись - конец директории
                                        PrintfQEMU("[FAT32] fat32_list_dir: end of directory, count = %d\n", count);
                                        kfree(sector); 
                                        return count; 
                                }
                                if (ent->attr==0x0F) {
                                        fat32_lfn_entry_t *lfn = (fat32_lfn_entry_t*)ent;
                                        // Надёжная валидация LFN-записи
                                        if (lfn->attr != 0x0F || lfn->type != 0) { lfn_present = 0; continue; }
                                        int ord = lfn->order & 0x1F;        // 1..N
                                        if (lfn->order & 0x40) {
                                                /* это начало новой цепочки LFN – очищаем буфер */
                                                memset(lfn_parts, 0, sizeof(lfn_parts));
                                        }
                                        if (ord>0 && ord<=20) {
                                                lfn_copy_part(lfn_parts[ord-1], lfn);
                                                if (lfn->order & 0x40) lfn_present = ord; // последний элемент
                                        } else {
                                                // некорректный номер части — сбрасываем цепочку
                                                lfn_present = 0;
                                        }
                                        continue;
                                }
                                if (ent->name[0]==0xE5) { lfn_present=0; continue; } // удалённая
                                if (count>=max_entries) { 
                                        PrintfQEMU("[FAT32] fat32_list_dir: max entries reached\n");
                                        kfree(sector); 
                                        return count; 
                                }

                                // --- заполняем выходную структуру ---
                                fat32_entry_t *dst = &out[count];
                                memset(dst,0,sizeof(*dst));
                                if (lfn_present) {
                                        /* склеиваем части LFN в правильном порядке */
                                        dst->name[0] = '\0';
                                        for (int i = lfn_present - 1; i >= 0; i--) {
                                                int len = strlen(lfn_parts[i]);
                                                int pos = strlen(dst->name);
                                                for(int k=0;k<len && pos < FAT32_MAX_NAME; k++)
                                                        dst->name[pos++] = lfn_parts[i][k];
                                                dst->name[pos] = '\0';
                                        }
                                } else {
                                        shortname_to_string(ent->name, dst->name);
                                }
                                dst->attr = ent->attr;
                                dst->first_cluster = ((uint32_t)ent->first_cluster_high<<16) | ent->first_cluster_low;
                                dst->size = ent->file_size;

                                PrintfQEMU("[FAT32] fat32_list_dir: found entry %d: %s (attr=0x%02x, cluster=%u)\n", 
                                                  count, dst->name, dst->attr, dst->first_cluster);
                                count++;
                                lfn_present = 0; // сброс для следующего файла
                        }
                }
                cl = fat32_get_next_cluster(drive, cl);
        }
        PrintfQEMU("[FAT32] fat32_list_dir: finished, count = %d\n", count);
        kfree(sector);
        return count;
}

/* Упрощённая обёртка для совместимости: возвращаем только короткие записи
 * (LFN игнорируются). Старый код shell.c продолжит работать, хотя длинные
 * имена будут скрыты. */
int fat32_read_dir(uint8_t drive, uint32_t cluster,
                                   fat32_dir_entry_t* entries, int max_entries) {
        uint8_t *sector = (uint8_t*)kmalloc(512);
        if (!sector) return -1;
        int count=0;
        uint32_t cl = cluster;
        while (cl < 0x0FFFFFF8) {
                for (uint8_t s=0; s<fat32_bpb.sectors_per_cluster; s++) {
                        uint32_t lba = fat32_cluster_to_lba(cl)+s;
                        if (ata_read_sector(drive, lba, sector)!=0) { kfree(sector); return -2; }
                        for (int off=0; off<512; off+=32) {
                                fat32_dir_entry_t *ent = (fat32_dir_entry_t*)&sector[off];
                                if (ent->name[0]==0x00) { kfree(sector); return count; }
                                if (ent->attr==0x0F || ent->name[0]==0xE5) continue; // пропускаем LFN и удалённые
                                if (count>=max_entries) { kfree(sector); return count; }
                                /* копируем 32-байтную запись в выходной массив (src,dst) */
                                for (int j=0;j<sizeof(fat32_dir_entry_t);j++)
                                        ((uint8_t*)&entries[count])[j] = ((uint8_t*)ent)[j];
                                count++;
                        }
                }
                cl = fat32_get_next_cluster(drive, cl);
        }
        kfree(sector);
        return count;
}

/* --------------------- Прочитать файл целиком -------------------------*/
int fat32_read_file(uint8_t drive, uint32_t first_cluster,
                                        uint8_t* buf, uint32_t size) {
        if (first_cluster<2) return -1;
        uint32_t cluster = first_cluster;
        uint32_t total   = 0;
        uint8_t *sector  = (uint8_t*)kmalloc(512);
        if (!sector) return -2;

        while (cluster < 0x0FFFFFF8 && total < size) {
                for (uint8_t s=0; s<fat32_bpb.sectors_per_cluster; s++) {
                        uint32_t lba = fat32_cluster_to_lba(cluster)+s;
                        if (ata_read_sector(drive, lba, sector)!=0) { 
                                kfree(sector); 
                                return -3; 
                        }
                        uint32_t copy = (size-total>512)?512:(size-total);
                        memcpy(buf + total, sector, copy);   /* src = sector, dst = buf+total (src,dst,len) */
                        total += copy;
                        if (total>=size) break;
                }
                cluster = fat32_get_next_cluster(drive, cluster);
        }
        kfree(sector);
        return total;
}

/* --------------- Заглушки для записи (пока не реализованы) ------------*/
int fat32_write_file(uint8_t drive, const char* path, const uint8_t* buf, uint32_t size){ (void)drive; (void)path; (void)buf; (void)size; return -1; }
/* старый stub fat32_create_file удалён */
int fat32_write_file_data(uint8_t drive,const char*name,const uint8_t*buf,uint32_t size,uint32_t offset){
        if(!name||!buf||size==0) return -1;

        /* --- ищем файл в текущем каталоге --- */
        fat32_entry_t *list = (fat32_entry_t*)kmalloc(64*sizeof(fat32_entry_t));
        if (!list) return -1;
        int n = fat32_list_dir(drive, current_dir_cluster, list, 64);
        int idx=-1;
        for(int i=0;i<n;i++) if(!(list[i].attr&0x10))
                if(strcasecmp_ascii(list[i].name,name)==0){ idx=i; break; }

        if(idx==-1){
                /* создаём файл */
                if(offset!=0){ return -1; }
                if(fat32_create_file(drive,name)!=0) {kfree(list); return -1;}
                n = fat32_list_dir(drive, current_dir_cluster, list, 64);
                for(int i=0;i<n;i++) if(!(list[i].attr&0x10))
                        if(strcasecmp_ascii(list[i].name,name)==0){ idx=i; break; }
                if(idx==-1) {kfree(list); return -1;}
        }

        fat32_entry_t *ent = &list[idx];
        uint32_t file_size = ent->size;
        uint32_t first_cluster = ent->first_cluster;
        if(first_cluster==0){ /* allocate first cluster */
                uint32_t cl = find_free_cluster(drive);
                if(!cl) {kfree(list); return -1;}
                fat_write_fat_entry(drive, cl, 0x0FFFFFFF);
                first_cluster = cl;
                ent->first_cluster = cl;
        }

        /* --- обеспечиваем достаточно кластеров --- */
        uint32_t cluster_size = fat32_bpb.sectors_per_cluster * 512;
        if (cluster_size == 0) cluster_size = 512; /* страховка от деления на ноль */
        uint32_t need_size = offset + size;
        uint32_t need_clusters = (need_size + cluster_size -1)/cluster_size;

        uint32_t cl = first_cluster; uint32_t chain_len=1;
        while(1){
                uint32_t next = fat32_get_next_cluster(drive, cl);
                if(next>=0x0FFFFFF8) break;
                chain_len++; cl=next;
        }
        while(chain_len<need_clusters){
                uint32_t newcl = find_free_cluster(drive);
                if(!newcl) {kfree(list); return -1;}
                fat_write_fat_entry(drive, cl, newcl);
                fat_write_fat_entry(drive, newcl, 0x0FFFFFFF);
                chain_len++; cl=newcl;
        }

        /* --- запись --- */
        uint32_t pos=0; uint32_t cur_off=offset; cl = first_cluster;
        uint32_t skip = cur_off/cluster_size;
        for(uint32_t i=0;i<skip;i++){ cl = fat32_get_next_cluster(drive, cl); }

        uint8_t *sector = (uint8_t*)kmalloc(512);
        if (!sector) {kfree(list); return -1;}
        while(pos<size){
                uint32_t within = cur_off % cluster_size;
                uint32_t sec_in_cluster = within / 512;
                uint32_t sec_off = within % 512;
                uint32_t lba = fat32_cluster_to_lba(cl)+sec_in_cluster;
                if(sec_off==0 && (size-pos)>=512){
                        /* можем писать полный сектор */
                        if(ata_write_sector(drive, lba, (uint8_t*)buf+pos)!=0) { kfree(sector); return -1; }
                        pos+=512; cur_off+=512;
                } else {
                        /* читаем сектор, модифицируем */
                        if(ata_read_sector(drive, lba, sector)!=0) { kfree(sector); return -1; }
                        uint32_t chunk = 512-sec_off; if(chunk>size-pos) chunk=size-pos;
                        /* копируем данные из пользовательского буфера в считанный сектор */
                        memcpy(sector+sec_off, (uint8_t*)buf+pos, chunk);
                        if(ata_write_sector(drive, lba, sector)!=0) { kfree(sector); return -1; }
                        pos+=chunk; cur_off+=chunk;
                }
                if((cur_off % cluster_size)==0 && pos<size){
                        cl = fat32_get_next_cluster(drive, cl);
                }
        }
        kfree(sector);
        /* --- обновляем размер, если увеличился --- */
        if(need_size>file_size){
                ent->size = need_size;
                /* найти и обновить запись в каталоге (SFN) */
                uint8_t *sect = (uint8_t*)kmalloc(512);
                if (!sect) {kfree(list); return -1;}
                for(uint8_t sc=0; sc<fat32_bpb.sectors_per_cluster; sc++){
                        uint32_t lba = fat32_cluster_to_lba(current_dir_cluster)+sc;
                        if(ata_read_sector(drive,lba,sect)!=0) { kfree(sect); return -1; }
                        for(int off=0; off<512; off+=32){
                                fat32_dir_entry_t *e = (fat32_dir_entry_t*)&sect[off];
                                if((e->attr&0x0F)==0x0F) continue;
                                char tmp[64]; shortname_to_string(e->name,tmp);
                                if(strcasecmp_ascii(tmp, ent->name)==0){
                                        e->file_size = need_size;
                                        e->first_cluster_high = (first_cluster>>16)&0xFFFF; /* запись SFN всё ещё содержит high/low */
                                        e->first_cluster_low = first_cluster & 0xFFFF;
                                        if(ata_write_sector(drive,lba,sect)!=0) { kfree(sect); return -1; }
                                        sc=0xFF; break;
                                }
                        }
                }
                kfree(sect);
        }
        kfree(list);

        /* --- операция завершена: сброс кеша FAT, чтобы следующие вызовы
           (например cd) видели уже записанные изменения --- */
        cached_fat_sector = 0xFFFFFFFF;
        next_free_hint        = 2;

        return size;
}

int fat32_read_file_data(uint8_t d,const char*p,uint8_t*b,uint32_t s,uint32_t o){(void)d;(void)p;(void)b;(void)s;(void)o;return -1;}

/* -------------------------------------------------------------
 *                  Простейшая реализация разрешения пути
 * -----------------------------------------------------------*/
int fat32_resolve_path(uint8_t drive, const char* path, uint32_t* target_cluster) {
        PrintfQEMU("[FAT32] fat32_resolve_path: %s\n", path ? path : "null");
        if (!path || !target_cluster) {
                PrintfQEMU("[FAT32] fat32_resolve_path: invalid parameters\n");
                return -1;
        }

        /* Снимаем возможный префикс "X:\" или "X:/" (номер диска) */
        if (path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
                /* если после префикса ничего нет – это корень */
                if (path[3] == '\0') {
                        *target_cluster = root_dir_first_cluster;
                        PrintfQEMU("[FAT32] fat32_resolve_path: root dir (prefix), cluster = %u\n", *target_cluster);
                        return 0;
                }
                /* пропускаем "X:\" */
                path += 3;
        }

        /* Абсолютный корень */
        if ((path[0]=='/' || path[0]=='\\') && path[1]=='\0') {
                *target_cluster = root_dir_first_cluster;
                PrintfQEMU("[FAT32] fat32_resolve_path: root dir, cluster = %u\n", *target_cluster);
                return 0;
        }

        /* Текущий каталог */
        if (path[0]=='\0' || (path[0]=='.' && path[1]=='\0')) {
                *target_cluster = current_dir_cluster;
                PrintfQEMU("[FAT32] fat32_resolve_path: current dir, cluster = %u\n", *target_cluster);
                return 0;
        }

        /* Родитель */
        if (path[0]=='.' && path[1]=='.' && path[2]=='\0') {
                PrintfQEMU("[FAT32] fat32_resolve_path: parent dir\n");
                fat32_entry_t *list = (fat32_entry_t*)kmalloc(sizeof(fat32_entry_t) * 2);
                if (!list) {
                        PrintfQEMU("[FAT32] fat32_resolve_path: kmalloc failed for parent dir\n");
                        return -1;
                }
                int n = fat32_list_dir(drive, current_dir_cluster, list, 2);
                if (n<2) {
                        PrintfQEMU("[FAT32] fat32_resolve_path: parent dir failed\n");
                        kfree(list);
                        return -1;
                }
                *target_cluster = list[1].first_cluster;
                /* если ".." указывает на текущий каталог – считаем, что это корень */
                if (*target_cluster == current_dir_cluster || *target_cluster == 0)
                        *target_cluster = root_dir_first_cluster;
                PrintfQEMU("[FAT32] fat32_resolve_path: parent dir, cluster = %u\n", *target_cluster);
                kfree(list);
                return 0;
        }

        /* Определяем, с какой директории начинать поиск */
        uint32_t start_cluster;
        const char* search_path;
        
        if (path[0] == '/' || path[0] == '\\') {
                /* Абсолютный путь - начинаем с корня */
                start_cluster = root_dir_first_cluster;
                search_path = path + 1; /* Пропускаем начальный / */
                PrintfQEMU("[FAT32] fat32_resolve_path: absolute path, starting from root\n");
        } else {
                /* Относительный путь - начинаем с текущей директории */
                start_cluster = current_dir_cluster;
                search_path = path;
                PrintfQEMU("[FAT32] fat32_resolve_path: relative path, starting from current dir\n");
        }

        /* Обрабатываем путь по частям */
        char path_copy[256];
        strncpy(path_copy, search_path, sizeof(path_copy)-1);
        path_copy[sizeof(path_copy)-1] = '\0';
        
        // Выделяем память для всех итераций
        fat32_entry_t *list = (fat32_entry_t*)kmalloc(sizeof(fat32_entry_t) * 64);
        if (!list) {
                PrintfQEMU("[FAT32] fat32_resolve_path: kmalloc failed\n");
                return -1;
        }
        
        char* token = strtok(path_copy, "/\\");
        while (token) {
                PrintfQEMU("[FAT32] fat32_resolve_path: searching for component '%s' in cluster %u\n", token, start_cluster);
                int n = fat32_list_dir(drive, start_cluster, list, 64);
                if (n<0) { 
                        PrintfQEMU("[FAT32] fat32_resolve_path: fat32_list_dir failed\n");
                        kfree(list); 
                        return -1; 
                }
                PrintfQEMU("[FAT32] fat32_resolve_path: found %d entries\n", n);
                
                bool found = false;
                for (int i=0;i<n;i++) {
                        if (strcasecmp_ascii(list[i].name, token)==0) {
                                start_cluster = list[i].first_cluster;
                                PrintfQEMU("[FAT32] fat32_resolve_path: found %s, cluster = %u\n", token, start_cluster);
                                found = true;
                                break;
                        }
                }
                
                if (!found) {
                        PrintfQEMU("[FAT32] fat32_resolve_path: component '%s' not found\n", token);
                        kfree(list);
                        return -1;
                }
                
                token = strtok(NULL, "/\\");
        }
        
        kfree(list);
        *target_cluster = start_cluster;
        PrintfQEMU("[FAT32] fat32_resolve_path: final cluster = %u\n", *target_cluster);
        return 0;
}

int fat32_change_dir(uint8_t d,const char* p){
        uint32_t c;
        int r=fat32_resolve_path(d,p,&c);
        if(!r && c>=2){ current_dir_cluster=c; }
        return r;
}

/* Найти свободный кластер (значение 0 в FAT) */
static uint32_t find_free_cluster(uint8_t drive){
        if(total_clusters==0) return 0;
        uint32_t start = next_free_hint;
        for(uint32_t iter=0; iter<total_clusters; iter++){
                uint32_t cl = 2 + ((start -2 + iter) % total_clusters); /* диапазон 2..2+total_clusters-1 */
                if(fat32_get_next_cluster(drive, cl)==0x00000000){
                        next_free_hint = cl+1;
                        if(next_free_hint >= 2+total_clusters) next_free_hint = 2;
                        return cl;
                }
        }
        return 0; /* нет свободных */
}
/* Записать значение в FAT для указанного кластера */
static int fat_write_fat_entry(uint8_t drive, uint32_t cluster, uint32_t value){
        uint32_t fat_offset = cluster*4;
        for(uint8_t t=0;t<fat32_bpb.table_count;t++){
                uint32_t fat_sector = fat_start + t*sectors_per_fat + fat_offset/512;
                uint32_t ent_off        = fat_offset%512;
                uint8_t sector[512];
                if(ata_read_sector(drive,fat_sector,sector)!=0) return -1;
                *(uint32_t*)&sector[ent_off] = value & 0x0FFFFFFF;
                if(ata_write_sector(drive,fat_sector,sector)!=0) return -1;
        }
        cached_fat_sector = 0xFFFFFFFF;
        return 0;
}
/* Подготовить SFN из long_name (упрощённо) */
static void make_sfn(const char *longname, char sfn[11]){
        memset(sfn,' ',11);
        int len=strlen(longname); int dot=-1;
        for(int i=0;i<len;i++) if(longname[i]=='.'){dot=i;break;}
        if(dot==-1){
                for(int i=0;i<len && i<8;i++) sfn[i]=toupper_ascii(longname[i]);
        } else {
                for(int i=0;i<dot && i<8;i++) sfn[i]=toupper_ascii(longname[i]);
                for(int i=dot+1,j=8;i<len && j<11;i++,j++) sfn[j]=toupper_ascii(longname[i]);
        }
}
/* Записать последовательность LFN+SFN в каталог (один сектор, без расширения) */
static int dir_write_entries(uint8_t drive, uint32_t lba, int offset, const uint8_t *entries, int count){
        uint8_t sector[512];
        if(ata_read_sector(drive,lba,sector)!=0) return -1;
        /* копируем записи по байтам во внутренний буфер сектора */
        for(int i=0;i<count*32;i++)
                sector[offset+i] = entries[i];
        if(ata_write_sector(drive,lba,sector)!=0) return -1;
        return 0;
}

/* Создать файл (пустой) с длинным именем в текущем каталоге */
int fat32_create_file(uint8_t drive, const char* name){
        /* Подготовка SFN */
        char sfn[11]; make_sfn(name,sfn);
        uint8_t checksum = shortname_checksum(sfn);
        int namelen=strlen(name);
        int lfn_entries = (namelen+12)/13;

        /* Собираем массив будущих записей */
        int total_entries = lfn_entries+1;
        uint8_t *buf = (uint8_t*)kmalloc(total_entries*32); if(!buf) return -1;
        memset(buf,0,total_entries*32);
        /* LFN – номера 1..N; запись с 0x40 (последняя) содержит начало имени */
        for(int seq=lfn_entries; seq>=1; seq--){
                int buf_idx = lfn_entries - seq;                          /* положение в буфере */
                fat32_lfn_entry_t *lfn=(fat32_lfn_entry_t*)&buf[buf_idx*32];
                lfn->order = seq;
                if(seq==lfn_entries) lfn->order |= 0x40;          /* последняя часть */
                lfn->attr  = 0x0F; lfn->type=0; lfn->checksum=checksum; lfn->first_cluster_low=0;

                int start = (seq-1)*13;                                           /* смещение в имени */
                for(int j=0;j<13;j++){
                        uint16_t ch = 0xFFFF;
                        if(start+j < namelen) ch = (uint8_t)name[start+j];
                        uint16_t *dst = (j<5)? &lfn->name1[j] : (j<11)? &lfn->name2[j-5] : &lfn->name3[j-11];
                        *dst = ch;
                }
        }
        /* SFN entry */
        fat32_dir_entry_t *s = (fat32_dir_entry_t*)&buf[lfn_entries*32];
        for(int i=0;i<11;i++) s->name[i] = sfn[i];
        s->attr = 0x20; /* file */
        s->file_size=0; s->first_cluster_high=0; s->first_cluster_low=0;

        /* Найти место в текущем каталоге */
        uint32_t cl=current_dir_cluster;
        uint8_t sector[512];
        while(1){
                for(uint8_t sec=0;sec<fat32_bpb.sectors_per_cluster;sec++){
                        uint32_t lba=fat32_cluster_to_lba(cl)+sec;
                        if(ata_read_sector(drive,lba,sector)!=0){kfree(buf);return -1;}
                        for(int off=0;off<=512-32*total_entries;off+=32){
                                int free_ok=1;
                                for(int e=0;e<total_entries;e++) if(sector[off+e*32]!=0x00 && sector[off+e*32]!=0xE5){free_ok=0;break;}
                                if(free_ok){
                                        /* пишем наши записи в сектор */
                                        for(int i=0;i<total_entries*32;i++)
                                                sector[off+i] = buf[i];
                                        int end=off+total_entries*32;
                                        if(end<512) sector[end]=0x00;
                                        if(ata_write_sector(drive,lba,sector)!=0){kfree(buf);return -1;}
                                        kfree(buf); return 0;
                                }
                                /* конец каталога метка 0x00 */
                                if(sector[off]==0x00){
                                        /* достаточно ли места? если нет, сдвигаем конец */
                                        memset(&sector[off],0x00,512-off); /* clear to end*/
                                        for(int i=0;i<total_entries*32;i++)
                                                sector[off+i] = buf[i];
                                        int end=off+total_entries*32;
                                        if(end<512) sector[end]=0x00;
                                        if(ata_write_sector(drive,lba,sector)!=0){kfree(buf);return -1;}
                                        kfree(buf); return 0;
                                }
                        }
                }
                /* нет места, нужно расширить каталог */
                uint32_t next = fat32_get_next_cluster(drive, cl);
                if(next>=0x0FFFFFF8){ /* allocate new */
                        uint32_t newcl = find_free_cluster(drive); if(!newcl){kfree(buf);return -1;}
                        fat_write_fat_entry(drive, cl, newcl);
                        fat_write_fat_entry(drive, newcl, 0x0FFFFFFF);
                        /* zero new cluster */
                        uint8_t zero[512]; memset(zero,0,512);
                        for(uint8_t sct=0;sct<fat32_bpb.sectors_per_cluster;sct++) ata_write_sector(drive,fat32_cluster_to_lba(newcl)+sct,zero);
                        cl=newcl;
                } else cl=next;
        }
}

int fat32_create_dir(uint8_t drive, const char* name){
        /* create directory entry first (similar to file) */
        char sfn[11]; make_sfn(name,sfn); uint8_t checksum=shortname_checksum(sfn);
        int namelen=strlen(name); int lcnt=(namelen+12)/13; int total=lcnt+1;
        uint8_t *buf = (uint8_t*)kmalloc(total*32); if(!buf) return -1; memset(buf,0,total*32);
        for(int seq=lcnt; seq>=1; seq--){
                int buf_idx = lcnt-seq;
                fat32_lfn_entry_t *lfn=(fat32_lfn_entry_t*)&buf[buf_idx*32];
                lfn->order = seq;
                if(seq==lcnt) lfn->order |= 0x40;
                lfn->attr=0x0F; lfn->type=0; lfn->checksum=checksum; lfn->first_cluster_low=0;
                int start=(seq-1)*13;
                for(int j=0;j<13;j++){
                        uint16_t ch=0xFFFF; if(start+j<namelen) ch=(uint8_t)name[start+j];
                        uint16_t *dst=(j<5)?&lfn->name1[j]:(j<11)?&lfn->name2[j-5]:&lfn->name3[j-11];
                        *dst=ch;
                }
        }
        fat32_dir_entry_t *d=(fat32_dir_entry_t*)&buf[lcnt*32];
        for(int i=0;i<11;i++) d->name[i] = sfn[i];
        d->attr=0x10; /* dir */
        uint32_t newcl=find_free_cluster(drive); if(!newcl){kfree(buf);return -1;}
        d->first_cluster_high=newcl>>16; d->first_cluster_low=newcl&0xFFFF; d->file_size=0;
        /* mark cluster as end */
        fat_write_fat_entry(drive, newcl, 0x0FFFFFFF);

        /* write dir entry into current directory */
        uint32_t cl=current_dir_cluster; uint8_t sector[512];
        while(1){
                for(uint8_t sct=0;sct<fat32_bpb.sectors_per_cluster;sct++){
                        uint32_t lba=fat32_cluster_to_lba(cl)+sct;
                        if(ata_read_sector(drive,lba,sector)!=0){kfree(buf);return -1;}
                        for(int off=0;off<=512-32*total;off+=32){
                                int free_ok=1; for(int e=0;e<total;e++) if(sector[off+32*e]!=0x00 && sector[off+32*e]!=0xE5){free_ok=0;break;}
                                if(free_ok){
                                        for(int i=0;i<total*32;i++)
                                                sector[off+i] = buf[i];
                                        int end=off+total*32;
                                        if(end<512) sector[end]=0x00;
                                        if(ata_write_sector(drive,lba,sector)!=0){kfree(buf);return -1;}
                                        kfree(buf);
                                        /* init new directory cluster with '.' and '..' */
                                        uint8_t dirsec[512]; memset(dirsec,0,512);
                                        /* . */
                                        memset(dirsec,' ',11); dirsec[0]='.'; dirsec[11]=0x10;
                                        *(uint16_t*)(&dirsec[20])=(newcl>>16)&0xFFFF; *(uint16_t*)(&dirsec[26])=newcl&0xFFFF;
                                        /* .. */
                                        memset(&dirsec[32],' ',11); dirsec[32]='.'; dirsec[33]='.'; dirsec[43]=0x10;
                                        *(uint16_t*)(&dirsec[52])=(current_dir_cluster>>16)&0xFFFF; *(uint16_t*)(&dirsec[58])=current_dir_cluster&0xFFFF;
                                        for(uint8_t sc=0;sc<fat32_bpb.sectors_per_cluster;sc++) ata_write_sector(drive,fat32_cluster_to_lba(newcl)+sc,dirsec);
                                return 0;
                                }
                                if(sector[off]==0x00){
                                        memset(&sector[off],0,512-off);
                                        for(int i=0;i<total*32;i++)
                                                sector[off+i] = buf[i];
                                        int end=off+total*32;
                                        if(end<512) sector[end]=0x00;
                                        if(ata_write_sector(drive,lba,sector)!=0){kfree(buf);return -1;}
                                        kfree(buf);
                                        /* init new dir cluster same as above */
                                        uint8_t dirsec[512]; memset(dirsec,0,512);
                                        memset(dirsec,' ',11); dirsec[0]='.'; dirsec[11]=0x10;
                                        *(uint16_t*)(&dirsec[20])=(newcl>>16)&0xFFFF; *(uint16_t*)(&dirsec[26])=newcl&0xFFFF;
                                        memset(&dirsec[32],' ',11); dirsec[32]='.'; dirsec[33]='.'; dirsec[43]=0x10;
                                        *(uint16_t*)(&dirsec[52])=(current_dir_cluster>>16)&0xFFFF; *(uint16_t*)(&dirsec[58])=current_dir_cluster&0xFFFF;
                                        for(uint8_t sc=0;sc<fat32_bpb.sectors_per_cluster;sc++) ata_write_sector(drive,fat32_cluster_to_lba(newcl)+sc,dirsec);
                                        return 0;
                                }
                        }
                }
                uint32_t next=fat32_get_next_cluster(drive,cl);
                if(next>=0x0FFFFFF8){uint32_t newc=find_free_cluster(drive); if(!newc){kfree(buf);return -1;} fat_write_fat_entry(drive,cl,newc); fat_write_fat_entry(drive,newc,0x0FFFFFFF); uint8_t zero[512]; memset(zero,0,512); for(uint8_t s=0;s<fat32_bpb.sectors_per_cluster;s++) ata_write_sector(drive,fat32_cluster_to_lba(newc)+s,zero); cl=newc;}
                else cl=next;
        }
}

void fat32_create_fs(uint8_t drive) {
        uint8_t bootloader_bin_[90] = {
                                0xEB, 0x21, 0x90,                         /* jmp short start (to 0x21) */
                                /* BPB (заполняется ниже) */
                                /* offset 0x21 (start): */
                                0xB8, 0x00, 0x7C,                         /* mov ax,0x7C00 */
                                0x8E, 0xD8,                                   /* mov ds,ax */
                                0xBE, 0x4E, 0x00,                         /* mov si,0x4E */
                                /* loop: */
                                0xAC,                                                 /* lodsb */
                                0x0C, 0x00,                                   /* or al,al */
                                0x74, 0x09,                                   /* jz hang */
                                0xB4, 0x0E,                                   /* mov ah,0x0E */
                                0xBB, 0x07, 0x00,                         /* mov bx,0x0007 */
                                0xCD, 0x10,                                   /* int 0x10 */
                                0xEB, 0xF3,                                   /* jmp short loop */
                                /* hang: */
                                0xF4,                                                 /* hlt */
                                0xEB, 0xFE,                                   /* jmp $ */
                                /* padding до 62 байт */
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        };
                        const char bootmsg[] = "This is not a bootable disk\r\n";
                        uint8_t* sector = (uint8_t*)kmalloc(512);
                        if (!sector) {
                                PrintfQEMU("[FAT32][ERR] fat32_createfs: error allocating memory\n");
                                return;
                        }
                        memset(sector, 0, 512);
                        // 1. Jump (3 байта)
                        sector[0] = 0xEB; sector[1] = 0x3C; sector[2] = 0x90;
                        // 2. BPB (с 3 по 0x3A)
                        strncpy((char*)&sector[3], "MSDOS5.0", 8); // OEM
                        *(uint16_t*)&sector[11] = 512; // bytes per sector
                        sector[13] = 1; // sectors per cluster
                        *(uint16_t*)&sector[14] = 32; // reserved sectors
                        sector[16] = 2; // FAT count
                        *(uint16_t*)&sector[17] = 0; // root entries (FAT32)
                        *(uint16_t*)&sector[19] = 0; // total sectors 16
                        sector[21] = 0xF8; // media
                        *(uint16_t*)&sector[22] = 0; // FAT size 16
                        *(uint16_t*)&sector[24] = 63; // sectors per track
                        *(uint16_t*)&sector[26] = 255; // heads
                        *(uint32_t*)&sector[28] = 0; // hidden sectors
                        *(uint32_t*)&sector[32] = 65536; // total sectors 32 (пример: 32 МБ)
                        *(uint32_t*)&sector[36] = 123; // FAT size 32
                        *(uint16_t*)&sector[44] = 0; // ext flags
                        *(uint16_t*)&sector[46] = 0; // FAT version
                        *(uint32_t*)&sector[48] = 2; // root cluster
                        *(uint16_t*)&sector[52] = 1; // FSInfo
                        *(uint16_t*)&sector[54] = 6; // backup boot sector
                        sector[64] = 0x80; // drive number
                        sector[66] = 0x29; // boot signature
                        *(uint32_t*)&sector[67] = 0x12345678; // volume id
                        strncpy((char*)&sector[71], "HATCHER        ", 11); // volume label
                        strncpy((char*)&sector[82], "FAT32   ", 8);          // fat type label
                        // 3. Код загрузчика (начиная с 0x3E)
                        for (int i = 0; i < (int)(sizeof(bootloader_bin_) - 3); i++)
                                sector[0x3E + i] = bootloader_bin_[3 + i];
                        // 4. Сообщение (начиная с 0x4E)
                        for (int i = 0; i < (int)sizeof(bootmsg); i++)
                                sector[0x4E + i] = bootmsg[i];
                        sector[510] = 0x55; sector[511] = 0xAA;
                        // Write Boot Sector
                        if (ata_write_sector(drive, 0, sector) != 0) {
                                PrintfQEMU("[FAT32][ERR] fat32_createfs: error writing boot sector\n");
                                return;
                        }
                        // FSInfo
                        memset(sector, 0, 512);
                        *(uint32_t*)&sector[0] = 0x41615252;
                        *(uint32_t*)&sector[484] = 0x61417272;
                        *(uint32_t*)&sector[488] = 0xFFFFFFFF;
                        *(uint32_t*)&sector[492] = 0xFFFFFFFF;
                        sector[510] = 0x55; sector[511] = 0xAA;
                        if (ata_write_sector(drive, 1, sector) != 0) {
                                PrintfQEMU("[FAT32][ERR] fat32_createfs: error writing fsinfo\n");
                                return;
                        }
                        // Clear FAT and root cluster
                        memset(sector, 0, 512);
                        for (int i = 0; i < 32; i++) {
                                ata_write_sector(drive, 32 + i, sector); // root directory
                        }
                        for (int i = 0; i < 123 * 2; i++) {
                                ata_write_sector(drive, 32 + 32 + i, sector); // FAT
                        }
                        PrintfQEMU("[FAT32][INFO] fat32_createfs: fat32 created\n");
}

// --- GLUE-КОД ДЛЯ FS_INTERFACE ---
#include <fs_interface.h>

struct fat32_fs_dir {
        uint32_t cluster;
        int entry_index;
        fat32_entry_t *entries;
        int entry_count;
};

struct fat32_fs_file {
        uint32_t first_cluster;
        uint32_t current_cluster;
        uint32_t position;
        uint32_t size;
        char path[256];
};

static fs_dir_t* fat32_fs_opendir(const char* path) {
        PrintfQEMU("[FAT32] fat32_fs_opendir: %s\n", path ? path : "null");
        
        if (!path) {
                PrintfQEMU("[FAT32] fat32_fs_opendir: null path\n");
                return NULL;
        }
        
        uint32_t cluster = 0;
        if (fat32_resolve_path(0, path, &cluster) != 0) {
                PrintfQEMU("[FAT32] fat32_fs_opendir: resolve_path failed\n");
                return NULL;
        }
        PrintfQEMU("[FAT32] fat32_fs_opendir: cluster = %u\n", cluster);
        
        struct fat32_fs_dir* fdir = (struct fat32_fs_dir*)kmalloc(sizeof(struct fat32_fs_dir));
        if (!fdir) {
                PrintfQEMU("[FAT32] fat32_fs_opendir: kmalloc failed for fdir\n");
                return NULL;
        }
        
        // Выделяем память для entries
        fdir->entries = (fat32_entry_t*)kmalloc(sizeof(fat32_entry_t) * 64);
        if (!fdir->entries) {
                PrintfQEMU("[FAT32] fat32_fs_opendir: kmalloc failed for entries\n");
                kfree(fdir);
                return NULL;
        }
        
        fdir->cluster = cluster;
        fdir->entry_index = 0;
        fdir->entry_count = 0;
        
        // Читаем содержимое директории
        int n = fat32_list_dir(0, cluster, fdir->entries, 64);
        if (n < 0) {
                PrintfQEMU("[FAT32] fat32_fs_opendir: fat32_list_dir failed\n");
                kfree(fdir->entries);
                kfree(fdir);
                return NULL;
        }
        
        fdir->entry_count = n;
        PrintfQEMU("[FAT32] fat32_fs_opendir: entry_count = %d\n", fdir->entry_count);
        
        fs_dir_t* dir = (fs_dir_t*)kmalloc(sizeof(fs_dir_t));
        if (!dir) {
                PrintfQEMU("[FAT32] fat32_fs_opendir: kmalloc failed for dir\n");
                kfree(fdir->entries);
                kfree(fdir);
                return NULL;
        }
        
        dir->private_data = fdir;
        strncpy(dir->path, path, sizeof(dir->path)-1);
        dir->path[sizeof(dir->path)-1] = '\0';
        
        PrintfQEMU("[FAT32] fat32_fs_opendir: success\n");
        return dir;
}

static int fat32_fs_readdir(fs_dir_t* dir, fs_dirent_t* out) {
        PrintfQEMU("[FAT32] fat32_fs_readdir: start\n");
        if (!dir || !dir->private_data || !out) {
                PrintfQEMU("[FAT32] fat32_fs_readdir: invalid parameters\n");
                return -1;
        }
        struct fat32_fs_dir* fdir = (struct fat32_fs_dir*)dir->private_data;
        if (fdir->entry_index >= fdir->entry_count) {
                PrintfQEMU("[FAT32] fat32_fs_readdir: no more entries\n");
                return -1;
        }
        fat32_entry_t* ent = &fdir->entries[fdir->entry_index];
        PrintfQEMU("[FAT32] fat32_fs_readdir: entry %d/%d: %s\n", fdir->entry_index + 1, fdir->entry_count, ent->name);
        strncpy(out->name, ent->name, sizeof(out->name)-1);
        out->name[sizeof(out->name)-1] = 0;
        out->attributes = (ent->attr & 0x10) ? FS_ATTR_DIRECTORY : 0;
        out->size = ent->size;
        out->create_time = 0;
        out->modify_time = 0;
        fdir->entry_index++; // Увеличиваем индекс после использования
        PrintfQEMU("[FAT32] fat32_fs_readdir: success\n");
        return 0;
}

static int fat32_fs_closedir(fs_dir_t* dir) {
        PrintfQEMU("[FAT32] fat32_fs_closedir: start\n");
        if (!dir) {
                PrintfQEMU("[FAT32] fat32_fs_closedir: null dir\n");
                return -1;
        }
        if (dir->private_data) {
                PrintfQEMU("[FAT32] fat32_fs_closedir: freeing private_data\n");
                struct fat32_fs_dir* fdir = (struct fat32_fs_dir*)dir->private_data;
                if (fdir->entries) {
                        kfree(fdir->entries);
                }
                kfree(dir->private_data);
        }
        PrintfQEMU("[FAT32] fat32_fs_closedir: freeing dir\n");
        kfree(dir);
        PrintfQEMU("[FAT32] fat32_fs_closedir: success\n");
        return 0;
}

static int fat32_fs_stat(const char* path, fs_stat_t* stat) {
        if (!path || !stat) return -1;
        
        // Получаем имя файла и родительскую директорию
        char* last_slash = strrchr(path, '/');
        if (!last_slash) last_slash = strrchr(path, '\\');
        const char* filename = last_slash ? last_slash + 1 : path;
        
        char parent_path[256];
        if (last_slash) {
                size_t len = (size_t)(last_slash - path);
                if (len >= sizeof(parent_path)) len = sizeof(parent_path) - 1;
                memcpy(parent_path, path, len);
                parent_path[len] = '\0';
        } else {
                strcpy(parent_path, ".");
        }
        
        // Находим родительскую директорию
        uint32_t parent_cluster = 0;
        if (fat32_resolve_path(0, parent_path, &parent_cluster) != 0) return -1;
        
        // Ищем файл в родительской директории
        fat32_entry_t *entries = (fat32_entry_t*)kmalloc(sizeof(fat32_entry_t) * 64);
        if (!entries) return -1;
        
        int count = fat32_list_dir(0, parent_cluster, entries, 64);
        if (count < 0) {
                kfree(entries);
                return -1;
        }
        
        for (int i = 0; i < count; i++) {
                if (strcasecmp_ascii(entries[i].name, filename) == 0) {
                        stat->size = entries[i].size;
                        stat->attributes = (entries[i].attr & 0x10) ? FS_ATTR_DIRECTORY : 0;
                        stat->create_time = 0;
                        stat->modify_time = 0;
                        stat->access_time = 0;
                        kfree(entries);
                        return 0;
                }
        }
        
        kfree(entries);
        return -1;
}

static fs_file_t* fat32_fs_open(const char* path, int mode) {
        PrintfQEMU("[FAT32] fat32_fs_open: %s\n", path ? path : "null");
        uint32_t cluster = 0;
        if (fat32_resolve_path(0, path, &cluster) != 0) {
                PrintfQEMU("[FAT32] fat32_fs_open: resolve_path failed\n");
                return NULL;
        }
        PrintfQEMU("[FAT32] fat32_fs_open: resolved cluster = %u\n", cluster);
        
        // Получаем информацию о файле через fat32_fs_stat
        fs_stat_t stat;
        if (fat32_fs_stat(path, &stat) != 0) {
                PrintfQEMU("[FAT32] fat32_fs_open: fat32_fs_stat failed\n");
                return NULL;
        }
        
        PrintfQEMU("[FAT32] fat32_fs_open: file size = %u\n", (uint32_t)stat.size);
        
        // Проверяем что размер файла не слишком большой
        if (stat.size > 0x1000000) { // 16MB максимум
                PrintfQEMU("[FAT32][ERROR] fat32_fs_open: file size too large: %u\n", (uint32_t)stat.size);
                return NULL;
        }
        
        struct fat32_fs_file* ffile = (struct fat32_fs_file*)kmalloc(sizeof(struct fat32_fs_file));
        if (!ffile) return NULL;
        ffile->first_cluster = cluster;
        ffile->current_cluster = cluster;
        ffile->position = 0;
        ffile->size = stat.size;
        strncpy(ffile->path, path, sizeof(ffile->path)-1);
        ffile->path[sizeof(ffile->path)-1] = '\0';
        
        fs_file_t* file = (fs_file_t*)kmalloc(sizeof(fs_file_t));
        if (!file) { kfree(ffile); return NULL; }
        file->private_data = ffile;
        file->size = stat.size;
        file->position = 0;
        file->mode = mode;
        
        PrintfQEMU("[FAT32] fat32_fs_open: success\n");
        return file;
}

static int fat32_fs_read(fs_file_t* file, void* buffer, size_t size) {
        PrintfQEMU("[FAT32] fat32_fs_read: start, size=%zu\n", size);
        if (!file || !file->private_data || !buffer) {
                PrintfQEMU("[FAT32] fat32_fs_read: invalid parameters\n");
                return -1;
        }
        struct fat32_fs_file* ffile = (struct fat32_fs_file*)file->private_data;

        PrintfQEMU("[FAT32] fat32_fs_read: position=%u, size=%u\n", ffile->position, ffile->size);

        // EOF
        if (ffile->position >= ffile->size) {
                PrintfQEMU("[FAT32] fat32_fs_read: EOF reached\n");
                return 0;
        }

        // Ограничиваем запрошенный размер доступными данными
        size_t available = ffile->size - ffile->position;
        if (size > available) {
                size = available;
                PrintfQEMU("[FAT32] fat32_fs_read: adjusted size to %zu\n", size);
        }
        if (size == 0) return 0;

        // Размер кластера
        uint32_t sectors_per_cluster = fat32_bpb.sectors_per_cluster ? fat32_bpb.sectors_per_cluster : 1;
        uint32_t cluster_size = sectors_per_cluster * 512;
        if (cluster_size == 0) cluster_size = 512;

        uint32_t pos = ffile->position;
        uint8_t* dst = (uint8_t*)buffer;
        size_t to_read = size;

        // Найти кластер, соответствующий текущей позиции
        uint32_t cl = ffile->first_cluster;
        if (cl < 2) return -1;
        uint32_t skip_clusters = pos / cluster_size;
        for (uint32_t i = 0; i < skip_clusters; i++) {
                cl = fat32_get_next_cluster(0, cl);
                if (cl >= 0x0FFFFFF8) return -1;
        }

        // Буфер одного сектора
        uint8_t* sector = (uint8_t*)kmalloc(512);
        if (!sector) return -1;

        while (to_read > 0 && cl < 0x0FFFFFF8) {
                uint32_t within_cluster = pos % cluster_size;
                uint32_t sec_in_cluster = within_cluster / 512;
                uint32_t sec_off = within_cluster % 512;

                // Переходим на следующий кластер, если превышаем его границы
                if (sec_in_cluster >= sectors_per_cluster) {
                        cl = fat32_get_next_cluster(0, cl);
                        if (cl >= 0x0FFFFFF8) break;
                        continue;
                }

                uint32_t lba = fat32_cluster_to_lba(cl) + sec_in_cluster;
                if (ata_read_sector(0, lba, sector) != 0) { kfree(sector); return -1; }

                uint32_t chunk = 512 - sec_off;
                if (chunk > to_read) chunk = (uint32_t)to_read;
                memcpy(dst, sector + sec_off, chunk);

                dst += chunk;
                pos += chunk;
                to_read -= chunk;

                // Если достигли конца кластера, перейти к следующему
                if ((pos % cluster_size) == 0 && to_read > 0) {
                        cl = fat32_get_next_cluster(0, cl);
                        if (cl >= 0x0FFFFFF8) break;
                }
        }

        kfree(sector);

        size_t read_total = size - to_read;
        ffile->position = pos;
        file->position = pos;
        return (int)read_total;
}

static int fat32_fs_write(fs_file_t* file, const void* buffer, size_t size) {
        if (!file || !file->private_data || !buffer) return -1;
        struct fat32_fs_file* ffile = (struct fat32_fs_file*)file->private_data;
        int result = fat32_write_file_data(0, ffile->path, (uint8_t*)buffer, size, ffile->position);
        if (result > 0) ffile->position += result;
        return result;
}

static int fat32_fs_close(fs_file_t* file) {
        if (!file) return -1;
        if (file->private_data) kfree(file->private_data);
        kfree(file);
        return 0;
}

static int fat32_fs_mkdir(const char* path) {
        if (!path) return -1;
        return fat32_create_dir(0, path);
}

static int fat32_fs_unlink(const char* path) {
        if (!path) return -1;
        // TODO: Реализовать удаление файла
        return -1;
}

static int fat32_fs_rename(const char* old_path, const char* new_path) {
        if (!old_path || !new_path) return -1;
        // TODO: Реализовать переименование
        return -1;
}

static int fat32_fs_seek(fs_file_t* file, int offset, int whence) {
        if (!file || !file->private_data) return -1;
        struct fat32_fs_file* ffile = (struct fat32_fs_file*)file->private_data;
        uint32_t new_pos = ffile->position;
        switch (whence) {
                case FS_SEEK_SET:
                        new_pos = (offset < 0) ? 0u : (uint32_t)offset;
                        break;
                case FS_SEEK_CUR:
                        if (offset < 0) {
                                uint32_t dec = (uint32_t)(-offset);
                                new_pos = (dec > new_pos) ? 0u : (new_pos - dec);
                        } else {
                                uint32_t inc = (uint32_t)offset;
                                if (0xFFFFFFFFu - new_pos < inc) new_pos = 0xFFFFFFFFu; else new_pos += inc;
                        }
                        break;
                case FS_SEEK_END: {
                        uint32_t base = ffile->size;
                        if (offset < 0) {
                                uint32_t dec = (uint32_t)(-offset);
                                new_pos = (dec > base) ? 0u : (base - dec);
                        } else {
                                uint32_t inc = (uint32_t)offset;
                                if (0xFFFFFFFFu - base < inc) new_pos = 0xFFFFFFFFu; else new_pos = base + inc;
                        }
                        break; }
                default:
                        return -1;
        }
        if (new_pos > ffile->size) new_pos = ffile->size;
        ffile->position = new_pos;
        file->position = new_pos;
        return (int)new_pos;
}

// --- ИНТЕГРАЦИЯ С СИСТЕМОЙ ---
static fs_interface_t fat32_interface = {
        fat32_init,                   // init
        fat32_fs_open,                          // open
        fat32_fs_close,                         // close
        fat32_fs_read,                          // read
        fat32_fs_write,                         // write
        fat32_fs_seek,                          // seek
        fat32_fs_opendir,                   // opendir
        fat32_fs_readdir,                   // readdir
        fat32_fs_closedir,                  // closedir
        fat32_fs_stat,                          // stat
        fat32_fs_mkdir,                         // mkdir
        fat32_fs_unlink,                        // unlink
        fat32_fs_rename                         // rename
};

extern "C" {
        fs_interface_t* fat32_get_interface() {
                return &fat32_interface;
        }

        int fat32_init() {
                // Быстрый выход, если диска нет — чтобы не зависать на попытках чтения
                ata_drive_t* d0 = ata_get_drive(0);
                if (!d0 || !d0->present) {
                        PrintfQEMU("[FAT32] skip: no drive 0 present, not mounting\n");
                        return -19; // -ENODEV
                }
                return fat32_mount(0);
        }
}
