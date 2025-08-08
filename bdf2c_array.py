#!/usr/bin/env python3
"""
BDF to C Array Converter
Конвертирует BDF файл в C массив формата:
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
"""

import sys
import re

def parse_bdf(filename):
    """Парсит BDF файл и возвращает словарь символов"""
    chars = {}
    current_char = None
    current_bitmap = []
    current_bbx = None
    in_char = False
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            if line.startswith('STARTCHAR'):
                in_char = True
                current_char = None
                current_bitmap = []
                current_bbx = None
                
            elif line.startswith('ENCODING'):
                if in_char:
                    match = re.search(r'ENCODING\s+(\d+)', line)
                    if match:
                        current_char = int(match.group(1))
                        
            elif line.startswith('BBX'):
                if in_char:
                    # BBX format: BBX width height x_offset y_offset
                    match = re.search(r'BBX\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(-?\d+)', line)
                    if match:
                        width = int(match.group(1))
                        height = int(match.group(2))
                        x_offset = int(match.group(3))
                        y_offset = int(match.group(4))
                        current_bbx = (width, height, x_offset, y_offset)
                        
            elif line.startswith('BITMAP'):
                current_bitmap = []
                
            elif line.startswith('ENDCHAR'):
                if in_char and current_char is not None:
                    chars[current_char] = {
                        'bitmap': current_bitmap,
                        'bbx': current_bbx
                    }
                in_char = False
                
            elif in_char and line and not line.startswith(('STARTCHAR', 'ENCODING', 'BBX', 'BITMAP', 'ENDCHAR')):
                # Это строка битовой карты
                if current_bitmap is not None:
                    current_bitmap.append(line)
    
    return chars

def hex_to_bytes(bitmap_lines, bbx=None):
    """Конвертирует строки битовой карты в байты с учетом позиционирования"""
    bytes_array = [0] * 8  # Инициализируем массив нулями
    
    if not bbx or not bitmap_lines:
        return bytes_array
    
    width, height, x_offset, y_offset = bbx
    
    # Вычисляем позицию в 8x8 блоке
    start_y = 8 - height - y_offset  # Сдвигаем вниз
    if start_y < 0:
        start_y = 0
    
    for i, line in enumerate(bitmap_lines):
        if i >= height:
            break
            
        y_pos = start_y + i
        if y_pos >= 8:
            break
            
        # Убираем пробелы и конвертируем hex в байт
        line = line.replace(' ', '').strip()
        if line:
            try:
                # Конвертируем hex строку в байт
                if len(line) == 1:
                    line = '0' + line
                elif len(line) > 2:
                    line = line[:2]
                
                byte_val = int(line, 16)
                
                # Обрабатываем ширину символа
                # Если ширина меньше 8, нужно сдвинуть биты влево
                if width < 8:
                    # Сдвигаем влево на (8 - width) позиций
                    shift = 8 - width
                    byte_val = byte_val << shift
                
                # Обрабатываем x_offset
                # x_offset может быть отрицательным (сдвиг влево) или положительным (сдвиг вправо)
                if x_offset != 0:
                    if x_offset > 0:
                        # Положительный offset - сдвигаем влево
                        byte_val = byte_val << x_offset
                    else:
                        # Отрицательный offset - сдвигаем вправо
                        byte_val = byte_val >> abs(x_offset)
                
                # Ограничиваем до 8 бит
                byte_val = byte_val & 0xFF
                
                bytes_array[y_pos] = byte_val
            except ValueError:
                pass
    
    return bytes_array

def generate_c_array(chars):
    """Генерирует C массив из символов"""
    output = []
    output.append("// Generated from BDF file")
    output.append("// Format: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},")
    output.append("")
    output.append("unsigned char font8x8_basic[512][8] = {")
    
    # Сортируем символы по коду
    sorted_chars = sorted(chars.items())
    
    for i in range(512):  # Генерируем 512 символов
        if i in chars:
            char_data = chars[i]
            bytes_array = hex_to_bytes(char_data['bitmap'], char_data['bbx'])
            hex_str = ", ".join([f"0x{byte:02X}" for byte in bytes_array])
            output.append(f"    {{{hex_str}}},   // U+{i:04X}")
        else:
            output.append(f"    {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},   // U+{i:04X}")
    
    output.append("};")
    return "\n".join(output)

def main():
    if len(sys.argv) != 2:
        print("Использование: python3 bdf2c_array.py <bdf_file>")
        sys.exit(1)
    
    bdf_file = sys.argv[1]
    
    try:
        print(f"Парсинг BDF файла: {bdf_file}")
        chars = parse_bdf(bdf_file)
        print(f"Найдено символов: {len(chars)}")
        
        print("Генерация C массива...")
        c_array = generate_c_array(chars)
        
        output_file = "font8x8_generated.h"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(c_array)
        
        print(f"C массив сохранен в файл: {output_file}")
        
    except FileNotFoundError:
        print(f"Ошибка: Файл {bdf_file} не найден")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 