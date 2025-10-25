#include <debug.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <pit.h>
#include <fs_interface.h>
#include <vga.h>

void outb(uint16_t port, uint8_t val) {
        asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

uint8_t inb(uint16_t port) {
        uint8_t ret;
        asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
        return ret;
}

void outw(uint16_t port, uint16_t val) {
        asm volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

uint16_t inw(uint16_t port) {
        uint16_t ret;
        asm volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
        return ret;
}

void PrintQEMU(const char* str) {
        for (int i = 0; str[i] != '\0'; i++) {
                outb(0xE9, str[i]);
        }
}

void outl(uint16_t port, uint32_t val) {
        asm volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

uint32_t inl(uint16_t port) {
        uint32_t ret;
        asm volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
        return ret;
}

extern "C" void qemu_log_printf(const char* format, ...) {
        va_list args;
        va_start(args, format);
        
        char buffer[1024];
        char* ptr = buffer;
        
        while (*format) {
                if (*format == '%') {
                        format++;
                        
                        // Обработка флагов ширины и точности
                        int width = 0;
                        int precision = 0;
                        int zero_pad = 0;
                        
                        // Проверяем флаг 0 для дополнения нулями
                        if (*format == '0') {
                                zero_pad = 1;
                                format++;
                        }
                        
                        // Читаем ширину
                        while (*format >= '0' && *format <= '9') {
                                width = width * 10 + (*format - '0');
                                format++;
                        }
                        
                        // Проверяем точность
                        if (*format == '.') {
                                format++;
                                while (*format >= '0' && *format <= '9') {
                                        precision = precision * 10 + (*format - '0');
                                        format++;
                                }
                        }
 
                        // Обработка длины ll для hex/dec
                        if (*format == 'l' && *(format+1) == 'l') {
                                // Длина ll
                                format += 2;
                                if (*format == 'x' || *format == 'X') {
                                        unsigned long long val = va_arg(args, unsigned long long);
                                        char temp[32]; int i = 0;
                                        if (val == 0) { temp[i++] = '0'; }
                                        else {
                                                while (val > 0) {
                                                        int digit = (int)(val % 16ULL);
                                                        temp[i++] = (*format == 'x')
                                                                ? ((digit < 10) ? '0' + digit : 'a' + digit - 10)
                                                                : ((digit < 10) ? '0' + digit : 'A' + digit - 10);
                                                        val /= 16ULL;
                                                }
                                        }
                                        while (i > 0) *ptr++ = temp[--i];
                                        format++;
                                        continue;
                                } else if (*format == 'u') {
                                        unsigned long long val = va_arg(args, unsigned long long);
                                        if (val == 0) { *ptr++ = '0'; }
                                        else { char temp[32]; int i=0; while (val>0){ temp[i++]='0'+(val%10); val/=10; } while(i>0){ *ptr++=temp[--i]; } }
                                        format++;
                                        continue;
                                } else if (*format == 'd' || *format == 'i') {
                                        long long val = va_arg(args, long long);
                                        if (val < 0) { *ptr++='-'; val = -val; }
                                        if (val == 0) { *ptr++ = '0'; }
                                        else { char temp[32]; int i=0; while (val>0){ temp[i++]='0'+(int)(val%10); val/=10; } while(i>0){ *ptr++=temp[--i]; } }
                                        format++;
                                        continue;
                                }
                                // если после ll неожиданный спецификатор — упадём в общий switch ниже с символом после ll
                        }

                        if (*format == 'l' && *(format+1) == 'l' && *(format+2) == 'u') {
                                // %llu
                                format += 2;
                                unsigned long long val = va_arg(args, unsigned long long);
                                if (val == 0) {
                                        *ptr++ = '0';
                                } else {
                                        char temp[32];
                                        int i = 0;
                                        while (val > 0) {
                                                temp[i++] = '0' + (val % 10);
                                                val /= 10;
                                        }
                                        while (i > 0) {
                                                *ptr++ = temp[--i];
                                        }
                                }
                                format++;
                                continue;
                        } else if (*format == 'l' && *(format+1) == 'u') {
                                // %lu
                                format++;
                                unsigned long val = va_arg(args, unsigned long);
                                if (val == 0) {
                                        *ptr++ = '0';
                                } else {
                                        char temp[32];
                                        int i = 0;
                                        while (val > 0) {
                                                temp[i++] = '0' + (val % 10);
                                                val /= 10;
                                        }
                                        while (i > 0) {
                                                *ptr++ = temp[--i];
                                        }
                                }
                                format++;
                                continue;
                        } else if (*format == 'u') {
                                // %u
                                unsigned int val = va_arg(args, unsigned int);
                                if (val == 0) {
                                        *ptr++ = '0';
                                } else {
                                        char temp[20];
                                        int i = 0;
                                        while (val > 0) {
                                                temp[i++] = '0' + (val % 10);
                                                val /= 10;
                                        }
                                        while (i > 0) {
                                                *ptr++ = temp[--i];
                                        }
                                }
                                format++;
                                continue;
                        } else if (*format == 'z') {
                                // handle size_t modifiers: %zu, %zx, %zX, %zd
                                format++;
                                if (*format == 'u') {
                                        unsigned long val = va_arg(args, unsigned long);
                                        if (val == 0) {
                                                *ptr++ = '0';
                                        } else {
                                                char temp[32];
                                                int i = 0;
                                                while (val > 0) {
                                                        temp[i++] = '0' + (val % 10);
                                                        val /= 10;
                                                }
                                                while (i > 0) {
                                                        *ptr++ = temp[--i];
                                                }
                                        }
                                        format++;
                                        continue;
                                }
                        }
                        
                        switch (*format) {
                                case 'd': {
                                        int val = va_arg(args, int);
                                        if (val < 0) {
                                                *ptr++ = '-';
                                                val = -val;
                                        }
                                        if (val == 0) {
                                                *ptr++ = '0';
                                        } else {
                                                char temp[20];
                                                int i = 0;
                                                while (val > 0) {
                                                        temp[i++] = '0' + (val % 10);
                                                        val /= 10;
                                                }
                                                while (i > 0) {
                                                        *ptr++ = temp[--i];
                                                }
                                        }
                                        break;
                                }
                                case 'x': {
                                        unsigned int val = va_arg(args, unsigned int);
                                        char temp[20];
                                        int i = 0;
                                        
                                        if (val == 0) {
                                                temp[i++] = '0';
                                        } else {
                                                while (val > 0) {
                                                        int digit = val % 16;
                                                        temp[i++] = (digit < 10) ? '0' + digit : 'a' + digit - 10;
                                                        val /= 16;
                                                }
                                        }
                                        
                                        // Дополняем нулями если нужно
                                        if (zero_pad && width > i) {
                                                while (i < width) {
                                                        temp[i++] = '0';
                                                }
                                        }
                                        
                                        // Выводим в обратном порядке
                                        while (i > 0) {
                                                *ptr++ = temp[--i];
                                        }
                                        break;
                                }
                                case 'X': {
                                        unsigned int val = va_arg(args, unsigned int);
                                        if (val == 0) {
                                                *ptr++ = '0';
                                        } else {
                                                char temp[20];
                                                int i = 0;
                                                while (val > 0) {
                                                        int digit = val % 16;
                                                        temp[i++] = (digit < 10) ? '0' + digit : 'A' + digit - 10;
                                                        val /= 16;
                                                }
                                                while (i > 0) {
                                                        *ptr++ = temp[--i];
                                                }
                                        }
                                        break;
                                }
                                case 'l': {
                                        format++;
                                        if (*format == 'x') {
                                                unsigned long val = va_arg(args, unsigned long);
                                                if (val == 0) {
                                                        *ptr++ = '0';
                                                } else {
                                                        char temp[20];
                                                        int i = 0;
                                                        while (val > 0) {
                                                                int digit = val % 16;
                                                                temp[i++] = (digit < 10) ? '0' + digit : 'a' + digit - 10;
                                                                val /= 16;
                                                        }
                                                        while (i > 0) {
                                                                *ptr++ = temp[--i];
                                                        }
                                                }
                                        } else if (*format == 'X') {
                                                unsigned long val = va_arg(args, unsigned long);
                                                if (val == 0) {
                                                        *ptr++ = '0';
                                                } else {
                                                        char temp[20];
                                                        int i = 0;
                                                        while (val > 0) {
                                                                int digit = val % 16;
                                                                temp[i++] = (digit < 10) ? '0' + digit : 'A' + digit - 10;
                                                                val /= 16;
                                                        }
                                                        while (i > 0) {
                                                                *ptr++ = temp[--i];
                                                        }
                                                }
                                        } else if (*format == 'u') {
                                                unsigned long val = va_arg(args, unsigned long);
                                                if (val == 0) {
                                                        *ptr++ = '0';
                                                } else {
                                                        char temp[20];
                                                        int i = 0;
                                                        while (val > 0) {
                                                                temp[i++] = '0' + (val % 10);
                                                                val /= 10;
                                                        }
                                                        while (i > 0) {
                                                                *ptr++ = temp[--i];
                                                        }
                                                }
                                        } else if (*format == 'd') {
                                                long val = va_arg(args, long);
                                                if (val < 0) {
                                                        *ptr++ = '-';
                                                        val = -val;
                                                }
                                                if (val == 0) {
                                                        *ptr++ = '0';
                                                } else {
                                                        char temp[20];
                                                        int i = 0;
                                                        while (val > 0) {
                                                                temp[i++] = '0' + (val % 10);
                                                                val /= 10;
                                                        }
                                                        while (i > 0) {
                                                                *ptr++ = temp[--i];
                                                        }
                                                }
                                        }
                                        break;
                                }
                                case 's': {
                                        const char* str = va_arg(args, const char*);
                                        while (*str) {
                                                *ptr++ = *str++;
                                        }
                                        break;
                                }
                                case 'c': {
                                        char c = va_arg(args, int);
                                        *ptr++ = c;
                                        break;
                                }
                                case 'p': {
                                        void* addr = va_arg(args, void*);
                                        unsigned long val = (unsigned long)addr;
                                        *ptr++ = '0';
                                        *ptr++ = 'x';
                                        if (val == 0) {
                                                *ptr++ = '0';
                                        } else {
                                                char temp[20];
                                                int i = 0;
                                                while (val > 0) {
                                                        int digit = val % 16;
                                                        temp[i++] = (digit < 10) ? '0' + digit : 'a' + digit - 10;
                                                        val /= 16;
                                                }
                                                while (i > 0) {
                                                        *ptr++ = temp[--i];
                                                }
                                        }
                                        break;
                                }
                                case '%': {
                                        *ptr++ = '%';
                                        break;
                                }
                                default: {
                                        *ptr++ = '%';
                                        *ptr++ = *format;
                                        break;
                                }
                        }
                } else {
                        *ptr++ = *format;
                }
                format++;
        }
        
        *ptr = '\0';
        
        PrintQEMU(buffer);
        
        va_end(args);
} 

static char g_mslog_buf[32];
static uint64_t g_time_us_base = 0;
static int g_time_base_set = 0;
extern "C" void klog_reset_time_base(void){ g_time_base_set = 0; g_time_us_base = 0; }
extern "C" const char* k_get_mslog(){
        // формат как в Linux: "   0.000000" с 6 дробными знаками
        // точность повышаем, читая текущий счётчик PIT для доли тика
        uint32_t freq = pit_frequency ? pit_frequency : 1000; // Гц
        if (freq == 0) freq = 1000;
        uint32_t divisor = PIT_FREQUENCY / freq; if (divisor == 0) divisor = 1;

        // Грубое количество тиков и текущее значение счётчика
        uint64_t ticks_snapshot = pit_ticks;
        uint16_t cnt = pit_get_current_count();

        // В режиме 2 (rate generator) счётчик монотонно убывает от divisor до 1 и опять перезагружается
        // Используем прошедшую часть тика как (divisor - cnt)
        uint32_t within = (divisor - (uint32_t)cnt);
        if (within >= divisor) within = 0;

        // Итоговое время в микросекундах: целые тики + доля тика
        // Время, прошедшее по целым тикам (1/freq сек каждый)
        uint64_t total_us = (ticks_snapshot * 1000000ULL) / (uint64_t)freq;
        // Плюс доля тика, измеренная напрямую в тактах базовой частоты PIT
        total_us += ((uint64_t)within * 1000000ULL) / (uint64_t)PIT_FREQUENCY;

        // Приведём отметку к времени относительно первой записи лога,
        // чтобы стартовать с 0.000000 как в dmesg
        if (!g_time_base_set){ g_time_us_base = total_us; g_time_base_set = 1; }
        uint64_t rel_us = (total_us >= g_time_us_base) ? (total_us - g_time_us_base) : 0;

        uint64_t sec = rel_us / 1000000ULL;
        uint32_t usec = (uint32_t)(rel_us % 1000000ULL);

        // собрать строку с выравниванием секунд до 4 позиций
        char* p = g_mslog_buf;
        char tmp[24]; int ti=0; uint64_t s=sec; if (s==0) tmp[ti++]='0'; else { while(s){ tmp[ti++] = (char)('0' + (s%10)); s/=10; } }
        int pad = 4 - ti; if (pad < 1) pad = 1; while (pad--) *p++ = ' ';
        while (ti) *p++ = tmp[--ti];
        *p++ = '.';
        // шесть цифр usec с ведущими нулями
        uint32_t divs[6] = {100000,10000,1000,100,10,1};
        for (int i=0;i<6;i++){
                uint32_t d = divs[i];
                uint32_t digit = (usec / d) % 10U;
                *p++ = (char)('0' + digit);
        }
        *p = '\0';
        return g_mslog_buf;
}

static void klog_write_prefix_buf(char* dst, size_t cap){
        if (!dst || cap==0) return;
        const char* ts = k_get_mslog();
        size_t i = 0;
        if (i < cap-1) dst[i++] = '[';
        for (const char* p = ts; *p && i < cap-1; ++p) dst[i++] = *p;
        if (i < cap-1) dst[i++] = ']';
        if (i < cap-1) dst[i++] = ' ';
        dst[i] = '\0';
}
static char buf[1024];
extern "C" int klog_vprintf(const char* fmt, va_list ap){
        if (!fmt) return 0;
        // Сформируем строку в локальный буфер и выведем через kprintf (экран+VFS) buf[0] = '\0';
        char* p = buf;
        klog_write_prefix_buf(p, sizeof(buf));
        size_t used = strlen(p);
        p += used;
        const char* f = fmt;
        while (*f && (p < buf + sizeof(buf) - 1)){
                if (*f != '%'){ *p++ = *f++; continue; }
                f++;
                bool zpad=false; int width=0; while (*f=='0'){ zpad=true; f++; }
                while (*f>='0'&&*f<='9'){ width = width*10 + (*f - '0'); f++; }
                int lcount=0; while (*f=='l'){ lcount++; f++; }
                char spec = *f ? *f++ : 0;
                auto out_num=[&](unsigned long long v,int base,bool upper){
                        const char* digs = upper?"0123456789ABCDEF":"0123456789abcdef";
                        char t[64]; int i=0; if (v==0) t[i++]='0'; else while(v){ t[i++]=digs[v%base]; v/=base; }
                        int pad = width - i; while (pad-- > 0 && p < buf + sizeof(buf) - 1) *p++ = zpad?'0':' ';
                        while (i && p < buf + sizeof(buf) - 1) *p++ = t[--i];
                };
                switch(spec){
                        case 'd': case 'i': {
                                long long v = (lcount>=2) ? va_arg(ap,long long) : (lcount==1) ? (long long)va_arg(ap,long) : (long long)va_arg(ap,int);
                                if (v<0){ *p++='-'; v=-v; }
                                out_num((unsigned long long)v,10,false);
                                break; }
                        case 'u': {
                                unsigned long long v = (lcount>=2) ? va_arg(ap,unsigned long long) : (lcount==1) ? (unsigned long long)va_arg(ap,unsigned long) : (unsigned long long)va_arg(ap,unsigned int);
                                out_num(v,10,false); break; }
                        case 'x': case 'X': {
                                bool upper = (spec=='X');
                                unsigned long long v = (lcount>=2) ? va_arg(ap,unsigned long long) : (lcount==1) ? (unsigned long long)va_arg(ap,unsigned long) : (unsigned long long)va_arg(ap,unsigned int);
                                out_num(v,16,upper); break; }
                        case 'p': {
                                unsigned long long v = (unsigned long long)va_arg(ap, void*);
                                if (p < buf + sizeof(buf) - 2){ *p++='0'; *p++='x'; }
                                out_num(v,16,false); break; }
                        case 's': {
                                const char* s = va_arg(ap,const char*);
                                if (!s) s = "(null)";
                                while (*s && p < buf + sizeof(buf) - 1) *p++ = *s++;
                                break; }
                        case 'c': { int ch = va_arg(ap,int); *p++ = (char)ch; break; }
                        case '%': { *p++ = '%'; break; }
                        default: { *p++ = '%'; if (spec) *p++ = spec; break; }
                }
        }
        *p = '\0';
        if (p==buf || *(p-1)!='\n') { *p++='\n'; *p='\0'; }
        kprintf("%s", buf);
        return (int)strlen(buf);
}

extern "C" int klog_printf(const char* fmt, ...){ va_list ap; va_start(ap, fmt); int r = klog_vprintf(fmt, ap); va_end(ap); return r; }