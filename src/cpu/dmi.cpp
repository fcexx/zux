#include <dmi.h>
#include <stdint.h>
#include <stddef.h>
extern "C" uint64_t g_smbios_addr = 0;
extern "C" uint32_t g_smbios_len  = 0;
#include <heap.h>
#include <debug.h>
#include <string.h>

struct __attribute__((packed)) SMBIOSEntry32 {
    char anchor[4];          // "_SM_"
    uint8_t checksum;
    uint8_t length;
    uint8_t major;
    uint8_t minor;
    uint16_t max_struct_size;
    uint8_t ep_revision;
    uint8_t formatted[5];
    char int_anchor[5];      // "_DMI_"
    uint8_t int_checksum;
    uint16_t table_length;
    uint32_t table_address;
    uint16_t structure_count;
    uint8_t bcd_revision;
};

static const char* copy_string(const char* src){
    if(!src||!*src) return "";
    // trim trailing non-printables (some tables end with \r)
    size_t len=strlen(src);
    while(len && (src[len-1]<32)) len--; // remove CR/LF/NULL padding
    char* dst=(char*)kmalloc(len+1);
    if(!dst) return "";
    memcpy(dst,src,len);
    dst[len]='\0';
    return dst;
}

static const char* bios_vendor="",*bios_version="",*bios_date="";
static const char* sys_vendor="",*product_name="",*product_sku="";
static const char* board_vendor="",*board_name="",*board_version="";

static uint8_t calc_sum(const uint8_t* p,size_t len){uint8_t s=0;for(size_t i=0;i<len;i++)s+=p[i];return s;}

static const SMBIOSEntry32* find_smbios(){
    for(uint32_t addr=0xF0000;addr<0x100000;addr+=16){
        const SMBIOSEntry32* ep=(const SMBIOSEntry32*)(uintptr_t)addr;
        if(memcmp(ep->anchor,"_SM_",4)==0 && calc_sum((const uint8_t*)ep,ep->length)==0)
            return ep;
    }
    return nullptr;
}

static const char* get_smbios_string(const char* strings_base,uint8_t idx){
    if(idx==0) return "";
    const char* s=strings_base;
    uint8_t cur=1;
    while(cur<idx && *s){ while(*s) ++s; ++s; ++cur; }
    if(cur==idx && *s) return s;
    return "";
}

int dmi_scan(){
    const SMBIOSEntry32* ep=find_smbios();
    if(!ep){ klog_printf("dmi: entry not found\n"); return -1; }
    const uint8_t* table=(const uint8_t*)(uintptr_t)ep->table_address;
    const uint8_t* p=table;
    for(uint16_t i=0;i<ep->structure_count;i++){
        uint8_t type=p[0];
        uint8_t len=p[1];
        const uint8_t* data=p;
        const char* strings_base=(const char*)p+len;
        // advance to next structure (strings terminated by double 0)
        const uint8_t* next=p+len;
        while(!(next[0]==0 && next[1]==0)) ++next;
        next+=2;
        // parse interested types
        if(type==0){ // BIOS Information
            uint8_t vendor_idx  = data[4];
            uint8_t ver_idx     = data[5];
            uint8_t date_idx    = data[8]; // SMBIOS spec: byte 8 – BIOS release date string
            bios_vendor  = copy_string(get_smbios_string(strings_base,vendor_idx));
            bios_version = copy_string(get_smbios_string(strings_base,ver_idx));
            bios_date    = copy_string(get_smbios_string(strings_base,date_idx));
        } else if(type==1){ // System
            sys_vendor=copy_string(get_smbios_string(strings_base,data[4]));
            product_name=copy_string(get_smbios_string(strings_base,data[5]));
            product_sku=copy_string(get_smbios_string(strings_base,data[19]));
        } else if(type==2){ // Board
            board_vendor=copy_string(get_smbios_string(strings_base,data[4]));
            board_name=copy_string(get_smbios_string(strings_base,data[5]));
            board_version=copy_string(get_smbios_string(strings_base,data[6]));
        }
        p=next;
    }
    klog_printf("dmi: BIOS  %s %s (%s)\n",bios_vendor,bios_version,bios_date);
    klog_printf("dmi: System %s %s (%s)\n",sys_vendor,product_name,product_sku);
    klog_printf("dmi: Board  %s %s (%s)\n",board_vendor,board_name,board_version);
    return 0;
}

const char* dmi_get_bios_vendor(){return bios_vendor;}
const char* dmi_get_bios_version(){return bios_version;}
const char* dmi_get_bios_date(){return bios_date;}
const char* dmi_get_sys_vendor(){return sys_vendor;}
const char* dmi_get_product_name(){return product_name;}
const char* dmi_get_product_sku(){return product_sku;}
const char* dmi_get_board_vendor(){return board_vendor;}
const char* dmi_get_board_name(){return board_name;}
const char* dmi_get_board_version(){return board_version;}
