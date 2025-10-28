#include <fs_interface.h>
#include <heap.h>
#include <string.h>
#include <debug.h>
#include <stddef.h>
#include <stdint.h>

struct VfsNode {
        char name[256];
        uint32_t attr; // FS_ATTR_DIRECTORY or FS_ATTR_ARCHIVE
        uint64_t size;
        uint8_t* data; // for files
        uint64_t capacity; // allocated size of data buffer
        VfsNode* parent;
        VfsNode* children; // singly-linked list
        VfsNode* next;
        uint8_t is_symlink; // 1 if symlink
        char link_target[256]; // symlink destination (NUL-terminated)
};

struct VfsFilePriv { VfsNode* node; uint64_t pos; };
struct VfsDirPriv { VfsNode* node; VfsNode* it; };

static VfsNode* vfs_root = nullptr;
static VfsNode* vfs_klog = nullptr; // /var/log/kern.log

static uint32_t to_attr(bool is_dir){ return is_dir ? FS_ATTR_DIRECTORY : FS_ATTR_ARCHIVE; }

static VfsNode* vfs_make_child(VfsNode* parent, const char* name, bool is_dir){
        VfsNode* n = (VfsNode*)kmalloc(sizeof(VfsNode));
        memset(n, 0, sizeof(VfsNode));
        strncpy(n->name, name, sizeof(n->name)-1);
        n->attr = to_attr(is_dir);
        n->capacity = 0;
        n->parent = parent;
        n->next = parent->children;
        parent->children = n;
        return n;
}

static VfsNode* vfs_lookup_path(const char* path){
        if (!path || !vfs_root) return nullptr;
        if (path[0] == '\0') return vfs_root;
        if (path[0] == '/') path++;
        VfsNode* cur = vfs_root;
        if (*path == '\0') return cur;
        char seg[256];
        while (*path){
                // extract segment
                size_t i=0; while (*path && *path!='/') { if (i<255) seg[i++]=*path; path++; }
                seg[i]='\0';
                if (strcmp(seg, ".") == 0) { if (*path=='/') path++; continue; }
                if (strcmp(seg, "..") == 0) { if (cur->parent) cur = cur->parent; if (*path=='/') path++; continue; }
                // find child
                VfsNode* ch = cur->children;
                while (ch && strncmp(ch->name, seg, 256)!=0) ch=ch->next;
                if (!ch) return nullptr;
                // follow absolute symlinks immediately
                if (ch->is_symlink && ch->link_target[0] == '/'){
                        VfsNode* target = vfs_lookup_path(ch->link_target);
                        if (!target) return nullptr;
                        cur = target;
                } else {
                        cur = ch;
                }
                if (*path=='/') path++;
        }
        return cur;
}

// cpio newc parser (very small)
static unsigned long from_hex(const char* s, int n){ unsigned long v=0; for(int i=0;i<n;i++){ char c=s[i]; v<<=4; if(c>='0'&&c<='9') v|=c-'0'; else if(c>='a'&&c<='f') v|=10+c-'a'; else if(c>='A'&&c<='F') v|=10+c-'A'; } return v; }

static uint32_t align4(uint32_t x){ return (x+3)&~3u; }
// throttle verbose VFS logging to avoid console flood during large cpio mounts
static int vfs_verbose_counter = 0;

int vfs_mount_from_cpio(const void* data, unsigned long size){
        vfs_root = (VfsNode*)kmalloc(sizeof(VfsNode));
        memset(vfs_root, 0, sizeof(VfsNode));
        strcpy(vfs_root->name, "/");
        vfs_root->attr = FS_ATTR_DIRECTORY;
        // prepare minimal POSIX-like tree: /dev and /var/log
        VfsNode* dev = vfs_make_child(vfs_root, "dev", true);
        (void)dev;
        VfsNode* var = vfs_make_child(vfs_root, "var", true);
        VfsNode* log = vfs_make_child(var, "log", true);
        vfs_klog = vfs_make_child(log, "kern.log", false);
        vfs_klog->data = nullptr;
        vfs_klog->size = 0;
        vfs_klog->capacity = 0;

        const uint8_t* p = (const uint8_t*)data;
        const uint8_t* p0 = p;
        const uint8_t* end = p + size;
        while (p + 110 <= end){
                // Проверяем magic "070701" вручную, чтобы избежать возможных проблем с memcmp
                bool magic_ok = (p[0]=='0' && p[1]=='7' && p[2]=='0' && p[3]=='7' && p[4]=='0' && p[5]=='1');
                if (!magic_ok){
                        // печать первых 6 байт на случай рассинхронизации
#ifdef K_QEMU_SERIAL_LOG
                        qemu_log_printf("[vfs] bad magic at +%lu: %02x %02x %02x %02x %02x %02x\n",
                                           (unsigned long)(p - p0), p[0],p[1],p[2],p[3],p[4],p[5]);
#endif
                        break;
                }
                const char* hdr = (const char*)p;
                unsigned long namesz = from_hex(hdr+94,8);
                unsigned long filesz = from_hex(hdr+54,8);
                unsigned long mode   = from_hex(hdr+14,8);
                const uint8_t* hdrStart = p;
                p += 110;
                // Bounds-check name field and copy into bounded buffer with NUL terminator
                if (p > end) break;
                unsigned long max_name_avail = (unsigned long)(end - p);
                if (namesz > max_name_avail) namesz = max_name_avail; // clamp
                char name_buf[512];
                unsigned long copy_n = namesz < sizeof(name_buf)-1 ? namesz : (unsigned long)sizeof(name_buf)-1;
                memcpy(name_buf, p, copy_n);
                name_buf[copy_n] = '\0';
                const char* name = name_buf;
                // Throttled header log: print every 128 entries or when file is large
                if ((vfs_verbose_counter++ & 127) == 0 || filesz > 0x100000ULL) {
                        // Print only safe-bounded name
#ifdef K_QEMU_SERIAL_LOG
                        qemu_log_printf("[vfs] hdr@+%lu namesz=%lu filesz=%lu mode=%08lx name='%s'\n",
                                           (unsigned long)(hdrStart - p0), copy_n, filesz, mode, name);
#endif
                }
                // move past name (including trailing NUL), then align p to 4 bytes
                p += namesz;
                p = (const uint8_t*)(((size_t)p + 3u) & ~(size_t)3u);
                if (strcmp(name, "TRAILER!!!") == 0) break;
                // normalize path: strip leading './' sequences and leading '/'
                char pathbuf[512]; strncpy(pathbuf, name, sizeof(pathbuf)-1); pathbuf[sizeof(pathbuf)-1]='\0';
                while (pathbuf[0]=='.' && pathbuf[1]=='/') { size_t L=strlen(pathbuf+2); memmove(pathbuf, pathbuf+2, L+1); }
                while (pathbuf[0]=='/') { size_t L=strlen(pathbuf+1); memmove(pathbuf, pathbuf+1, L+1); }
                if (pathbuf[0]=='\0') { p += align4((uint32_t)filesz); continue; }
                // detect types by c_mode (newc): S_IFMT=0170000, S_IFDIR=0040000, S_IFLNK=0120000
                bool is_dir = ((mode & 0170000) == 0040000);
                bool is_lnk = ((mode & 0170000) == 0120000);
                // strip trailing '/' only if present
                size_t plen = strlen(pathbuf);
                if (plen > 0 && pathbuf[plen-1] == '/') pathbuf[plen-1] = '\0';
                if (strcmp(pathbuf, ".") == 0){
                        // пропускаем явный корень
                        p += align4((uint32_t)filesz);
                        continue;
                }
                // walk
                VfsNode* cur = vfs_root; char* s = pathbuf; if (*s=='/') s++;
                while (*s){
                        char* slash = strchr(s, '/');
                        if (!slash){
                                // final component under 'cur'
                                VfsNode* exist = cur->children; while (exist && strcmp(exist->name, s)!=0) exist=exist->next;
                                if (!exist) exist = vfs_make_child(cur, s, is_dir);
                                if (!is_dir){
                                        if (is_lnk){
                                                exist->is_symlink = 1;
                                                size_t tlen = (filesz < sizeof(exist->link_target)-1) ? (size_t)filesz : sizeof(exist->link_target)-1;
                                                memset(exist->link_target, 0, sizeof(exist->link_target));
                                                if (tlen) memcpy(exist->link_target, p, tlen);
                                                // strip any trailing NULs/newlines
                                                size_t L = strlen(exist->link_target);
                                                while (L && (exist->link_target[L-1]=='\n' || exist->link_target[L-1]=='\0' || exist->link_target[L-1]=='\r')) { exist->link_target[L-1]=0; L--; }
                                                // Throttle symlink logs to avoid flooding
#ifdef K_QEMU_SERIAL_LOG
                                                if ((vfs_verbose_counter & 127) == 0 || filesz > 1024) qemu_log_printf("[vfs] symlink: path=%s target='%s' filesz=%lu\n", pathbuf, exist->link_target, filesz);
#endif
                                        } else if (filesz){
                                                // Всегда копируем в heap, чтобы не держать ссылки на модуль Multiboot (может быть за пределами identity-map)
#ifdef K_QEMU_SERIAL_LOG
                                                qemu_log_printf("[vfs] file: path=%s filesz=%lu\n", pathbuf, filesz);
#endif
                                                exist->size = filesz;
                                                exist->data = (uint8_t*)kmalloc(filesz);
                                                if (!exist->data) {
#ifdef K_QEMU_SERIAL_LOG
                                                        qemu_log_printf("[vfs] kmalloc failed for %s size=%lu, truncating to available\n", pathbuf, filesz);
#endif
                                                        size_t avail = (size_t)(end - (const uint8_t*)p);
                                                        if (avail > (size_t)filesz) avail = (size_t)filesz;
                                                        exist->data = (uint8_t*)kmalloc(avail);
                                                        if (exist->data) { memcpy(exist->data, p, avail); exist->size = avail; }
                                                } else {
                                                        // Ensure source pointer is within archive bounds before memcpy
                                                        size_t avail = (size_t)filesz;
                                                        if ((const uint8_t*)p + filesz > end) {
#ifdef K_QEMU_SERIAL_LOG
                                                                qemu_log_printf("[vfs] WARNING: cpio entry truncated for %s (filesz=%lu, available=%lu)\n",
                                                                                   pathbuf, filesz, (unsigned long)(end - (const uint8_t*)p));
#endif
                                                                avail = (size_t)(end - (const uint8_t*)p);
                                                                if (avail > (size_t)filesz) avail = (size_t)filesz;
                                                                exist->size = avail;
                                                        }
                                                        if (avail) memcpy(exist->data, p, avail);
                                                }
                                        }
                                }
                                if (filesz > 0x100000ULL) {
                                        // Large file - always log
#ifdef K_QEMU_SERIAL_LOG
                                        qemu_log_printf("[vfs] add %s %s size=%lu\n", pathbuf, is_dir?"dir":"file", filesz);
#endif
                                        klog_printf("cpio: WARNING: large file %s size=%lu\n", pathbuf, filesz);
                                } else {
                                        // Throttled add log
#ifdef K_QEMU_SERIAL_LOG
                                        if ((vfs_verbose_counter & 127) == 0) qemu_log_printf("[vfs] add %s %s size=%lu\n", pathbuf, is_dir?"dir":"file", filesz);
#endif

                                }
                                break;
                        } else {
                                *slash='\0';
                                // ensure directory exists
                                VfsNode* ch = cur->children; while (ch && strcmp(ch->name, s)!=0) ch=ch->next;
                                if (!ch){ ch = vfs_make_child(cur, s, true); }
                                cur = ch; s = slash+1;
                        }
                }
                // move past file data then align to 4 bytes (with bounds check)
                if ((unsigned long)(end - p) < filesz) filesz = (unsigned long)(end - p);
                p += filesz;
                p = (const uint8_t*)(((size_t)p + 3u) & ~(size_t)3u);
                // No yields during mount to avoid reentrancy in early boot
        }
#ifdef K_QEMU_SERIAL_LOG
        qemu_log_printf("[vfs] mounted cpio with root=%p\n", (void*)vfs_root);
#endif
        return 0;
}

// fs ops
static int vfs_init(){ return 0; }
static fs_file_t* vfs_open(const char* path, int mode){ (void)mode; VfsNode* n = vfs_lookup_path(path); if (!n || (n->attr & FS_ATTR_DIRECTORY)) return nullptr; fs_file_t* f=(fs_file_t*)kmalloc(sizeof(fs_file_t)); memset(f,0,sizeof(*f)); VfsFilePriv* pv=(VfsFilePriv*)kmalloc(sizeof(VfsFilePriv)); pv->node=n; pv->pos=0; f->private_data=pv; f->size=n->size; f->mode=mode; return f; }
static int vfs_close(fs_file_t* f){ if(!f) return -1; if (f->private_data) kfree(f->private_data); kfree(f); return 0; }
static int vfs_read(fs_file_t* f, void* buf, size_t sz){ if(!f||!f->private_data) return -1; VfsFilePriv* pv=(VfsFilePriv*)f->private_data; uint64_t rem = (pv->pos < pv->node->size) ? (pv->node->size - pv->pos) : 0; if (sz>rem) sz=(size_t)rem; if (sz){ memcpy(buf, pv->node->data + pv->pos, sz); pv->pos += sz; } return (int)sz; }
static int vfs_seek(fs_file_t* f, int off, int whence){ if(!f||!f->private_data) return -1; VfsFilePriv* pv=(VfsFilePriv*)f->private_data; uint64_t np = pv->pos; if(whence==FS_SEEK_SET) np = off; else if(whence==FS_SEEK_CUR) np += off; else if(whence==FS_SEEK_END) np = pv->node->size + off; if ((int64_t)np < 0) np = 0; if (np>pv->node->size) np=pv->node->size; pv->pos=np; return (int)np; }
static fs_dir_t* vfs_opendir(const char* path){ VfsNode* n=vfs_lookup_path(path); if(!n||!(n->attr&FS_ATTR_DIRECTORY)) return nullptr; fs_dir_t* d=(fs_dir_t*)kmalloc(sizeof(fs_dir_t)); memset(d,0,sizeof(*d)); strncpy(d->path,path?path:"/",sizeof(d->path)-1); VfsDirPriv* pv=(VfsDirPriv*)kmalloc(sizeof(VfsDirPriv)); pv->node=n; pv->it=n->children; d->private_data=pv; return d; }
static int vfs_readdir(fs_dir_t* dir, fs_dirent_t* ent){ if(!dir||!ent||!dir->private_data) return -1; VfsDirPriv* pv=(VfsDirPriv*)dir->private_data; VfsNode* it = pv->it; if(!it) return -1; memset(ent,0,sizeof(*ent)); strncpy(ent->name,it->name,sizeof(ent->name)-1); ent->attributes=it->attr; ent->size=it->size; pv->it = it->next; return 0; }
static int vfs_closedir(fs_dir_t* dir){ if(!dir) return -1; if(dir->private_data) kfree(dir->private_data); return 0; }
static int vfs_stat(const char* path, fs_stat_t* st){ VfsNode* n=vfs_lookup_path(path); if(!n||!st) return -1; memset(st,0,sizeof(*st)); st->size=n->size; st->attributes=n->attr; return 0; }
static int vfs_write(fs_file_t* f, const void* buf, size_t sz){
        if (!f || !f->private_data || !buf || sz==0) return -1;
        VfsFilePriv* pv = (VfsFilePriv*)f->private_data;
        VfsNode* n = pv->node;
        if (!n || (n->attr & FS_ATTR_DIRECTORY)) return -1;
        // append-only behavior for klog
        if (f->mode & FS_OPEN_APPEND) pv->pos = n->size;
        uint64_t need = pv->pos + sz;
        // ensure capacity
        if (need > n->capacity){
                uint64_t newcap = n->capacity ? n->capacity : 4096;
                while (newcap < need) newcap *= 2;
                uint8_t* nd = (uint8_t*)kmalloc((size_t)newcap);
                if (!nd) return -12; // ENOMEM
                if (n->data && n->size) memcpy(nd, n->data, (size_t)n->size);
                n->data = nd; n->capacity = newcap;
        }
        memcpy(n->data + pv->pos, buf, sz);
        if (need > n->size) n->size = need;
        pv->pos += sz;
        if (f->size < pv->pos) f->size = pv->pos;
        return (int)sz;
}
static int vfs_mkdir(const char*){ return -30; }
static int vfs_unlink(const char*){ return -30; }
static int vfs_rename(const char*, const char*){ return -30; }

static fs_interface_t vfs_if = {
        vfs_init,
        vfs_open,
        vfs_close,
        vfs_read,
        vfs_write,
        vfs_seek,
        vfs_opendir,
        vfs_readdir,
        vfs_closedir,
        vfs_stat,
        vfs_mkdir,
        vfs_unlink,
        vfs_rename
};

extern "C" fs_interface_t* vfs_get_interface(){ return &vfs_if; } 
extern "C" const char* vfs_readlink_target(const char* path){ VfsNode* n = vfs_lookup_path(path); if (!n || !n->is_symlink) return nullptr; return n->link_target; }

extern "C" void vfs_klog_append(const char* s, unsigned long n){
        if (!vfs_klog || !s || n==0) return;
        fs_file_t tf; memset(&tf,0,sizeof(tf)); VfsFilePriv pv; pv.node=vfs_klog; pv.pos=vfs_klog->size; tf.private_data=&pv; tf.size=vfs_klog->size; tf.mode = FS_OPEN_APPEND;
        (void)vfs_write(&tf, s, (size_t)n);
}

// Minimal devfs-like helpers for creating nodes under /dev at runtime
extern "C" int vfs_dev_create_dir(const char* path){
        if (!path || !vfs_root) return -1;
        // only absolute paths
        if (path[0] != '/') return -1;
        // find parent
        char *temp = (char*)kmalloc(512);
        if (!temp) return -1;
        strncpy(temp, path, sizeof(temp)-1); temp[sizeof(temp)-1]='\0';
        // strip trailing '/'
        size_t L = strlen(temp); if (L>1 && temp[L-1]=='/') temp[L-1]='\0';
        // locate parent directory
        char* last = strrchr(temp, '/');
        if (!last) return -1;
        char name[256];
        if (last == temp){ // parent is root
                strcpy(name, temp+1);
                if (name[0] == '\0') return 0; // it's "/"
                // ensure child exists
                VfsNode* cur = vfs_root;
                VfsNode* ch = cur->children; while (ch && strcmp(ch->name, name)!=0) ch=ch->next;
                if (!ch) (void)vfs_make_child(cur, name, true);
                kfree(temp);
                return 0;
        } else {
                *last = '\0';
                const char* base = last+1;
                strncpy(name, base, sizeof(name)-1); name[sizeof(name)-1]='\0';
                VfsNode* parent = vfs_lookup_path(temp);
                if (!parent || !(parent->attr & FS_ATTR_DIRECTORY)) return -1;
                VfsNode* ch = parent->children; while (ch && strcmp(ch->name, name)!=0) ch=ch->next;
                if (!ch) (void)vfs_make_child(parent, name, true);
                kfree(temp);
                return 0;
        }
}

extern "C" int vfs_dev_create_file(const char* path, const void* data, unsigned long size){
        if (!path || !vfs_root) return -1;
        if (path[0] != '/') return -1;
        char *temp = (char*)kmalloc(512);
        if (!temp) return -1;
        strncpy(temp, path, sizeof(temp)-1); temp[sizeof(temp)-1]='\0';
        size_t L = strlen(temp); if (L>1 && temp[L-1]=='/') temp[L-1]='\0';
        char* last = strrchr(temp, '/'); if (!last) return -1;
        char *name = (char*)kmalloc(256);
        if (!name) return -1;
        if (last == temp){ strcpy(name, temp+1); VfsNode* cur=vfs_root; VfsNode* ch=cur->children; while (ch&&strcmp(ch->name,name)!=0) ch=ch->next; if (!ch) ch=vfs_make_child(cur,name,false); if (ch){ if (size){ ch->data=(uint8_t*)kmalloc(size); if (ch->data && data) memcpy(ch->data,data,(size_t)size); ch->size=size; ch->capacity=size; } } return 0; }
        *last='\0'; const char* base=last+1; strncpy(name, base, sizeof(name)-1); name[sizeof(name)-1]='\0';
        VfsNode* parent = vfs_lookup_path(temp); if (!parent || !(parent->attr & FS_ATTR_DIRECTORY)) return -1;
        VfsNode* ch = parent->children; while (ch && strcmp(ch->name, name)!=0) ch=ch->next;
        if (!ch) ch = vfs_make_child(parent, name, false);
        if (ch){ if (size){ ch->data=(uint8_t*)kmalloc(size); if (ch->data && data) memcpy(ch->data,data,(size_t)size); ch->size=size; ch->capacity=size; } }
        kfree(temp);
        kfree(name);
        return 0;
}