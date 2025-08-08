#include <debug.h>
#include <stdarg.h>

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

void PrintfQEMU(const char* format, ...) {
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