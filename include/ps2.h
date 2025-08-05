#ifndef PS2_H
#define PS2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Инициализация PS/2 клавиатуры
void ps2_keyboard_init();

// Получить символ (блокирующая функция, как в Unix)
char kgetc();

// Проверить, есть ли доступные символы (неблокирующая)
int kgetc_available();

// Получить строку с поддержкой стрелок и редактирования
char* kgets(char* buffer, int max_length);

#ifdef __cplusplus
}
#endif

#endif // PS2_H
