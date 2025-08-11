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
    VfsNode* parent;
    VfsNode* children; // singly-linked list
    VfsNode* next;
};

struct VfsFilePriv { VfsNode* node; uint64_t pos; };
struct VfsDirPriv { VfsNode* node; VfsNode* it; };

static VfsNode* vfs_root = nullptr;

static uint32_t to_attr(bool is_dir){ return is_dir ? FS_ATTR_DIRECTORY : FS_ATTR_ARCHIVE; }

static VfsNode* vfs_make_child(VfsNode* parent, const char* name, bool is_dir){
    VfsNode* n = (VfsNode*)kmalloc(sizeof(VfsNode));
    memset(n, 0, sizeof(VfsNode));
    strncpy(n->name, name, sizeof(n->name)-1);
    n->attr = to_attr(is_dir);
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
        cur = ch;
        if (*path=='/') path++;
    }
    return cur;
}

// cpio newc parser (very small)
static unsigned long from_hex(const char* s, int n){ unsigned long v=0; for(int i=0;i<n;i++){ char c=s[i]; v<<=4; if(c>='0'&&c<='9') v|=c-'0'; else if(c>='a'&&c<='f') v|=10+c-'a'; else if(c>='A'&&c<='F') v|=10+c-'A'; } return v; }

static uint32_t align4(uint32_t x){ return (x+3)&~3u; }

int vfs_mount_from_cpio(const void* data, unsigned long size){
    vfs_root = (VfsNode*)kmalloc(sizeof(VfsNode));
    memset(vfs_root, 0, sizeof(VfsNode));
    strcpy(vfs_root->name, "/");
    vfs_root->attr = FS_ATTR_DIRECTORY;
    // ensure /dev exists and /dev/tty placeholder
    VfsNode* dev = vfs_make_child(vfs_root, "dev", true);
    (void)dev;

    const uint8_t* p = (const uint8_t*)data;
    const uint8_t* p0 = p;
    const uint8_t* end = p + size;
    while (p + 110 <= end){
        if (memcmp(p, "070701", 6) != 0){
            // печать первых 6 байт на случай рассинхронизации
            PrintfQEMU("[vfs] bad magic at +%lu: %02x %02x %02x %02x %02x %02x\n",
                       (unsigned long)(p - p0), p[0],p[1],p[2],p[3],p[4],p[5]);
            break;
        }
        const char* hdr = (const char*)p;
        unsigned long namesz = from_hex(hdr+94,8);
        unsigned long filesz = from_hex(hdr+54,8);
        unsigned long mode   = from_hex(hdr+14,8);
        const uint8_t* hdrStart = p;
        p += 110;
        const char* name = (const char*)p;
        PrintfQEMU("[vfs] hdr@+%lu namesz=%lu filesz=%lu mode=%08lx name='%s'\n",
                   (unsigned long)(hdrStart - p0), namesz, filesz, mode, name);
        // move past name (including trailing NUL), then align p to 4 bytes
        p += namesz;
        p = (const uint8_t*)(((size_t)p + 3u) & ~(size_t)3u);
        if (strcmp(name, "TRAILER!!!") == 0) break;
        // normalize path: strip leading './' sequences and leading '/'
        char pathbuf[512]; strncpy(pathbuf, name, sizeof(pathbuf)-1); pathbuf[sizeof(pathbuf)-1]='\0';
        while (pathbuf[0]=='.' && pathbuf[1]=='/') memmove(pathbuf, pathbuf+2, strlen(pathbuf+2)+1);
        while (pathbuf[0]=='/') memmove(pathbuf, pathbuf+1, strlen(pathbuf+1)+1);
        if (pathbuf[0]=='\0') { p += align4((uint32_t)filesz); continue; }
        // detect directory by c_mode (newc): S_IFMT=0170000, S_IFDIR=0040000
        bool is_dir = ((mode & 0170000) == 0040000);
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
                if (!is_dir && filesz){ exist->size = filesz; exist->data = (uint8_t*)kmalloc(filesz); memcpy(exist->data, p, filesz); }
                PrintfQEMU("[vfs] add %s %s size=%lu\n", pathbuf, is_dir?"dir":"file", filesz);
                break;
            } else {
                *slash='\0';
                // ensure directory exists
                VfsNode* ch = cur->children; while (ch && strcmp(ch->name, s)!=0) ch=ch->next;
                if (!ch){ ch = vfs_make_child(cur, s, true); }
                cur = ch; s = slash+1;
            }
        }
        // move past file data then align to 4 bytes
        p += filesz;
        p = (const uint8_t*)(((size_t)p + 3u) & ~(size_t)3u);
    }
    PrintfQEMU("[vfs] mounted cpio with root=%p\n", (void*)vfs_root);
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
static int vfs_write(fs_file_t*, const void*, size_t){ return -30; }
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