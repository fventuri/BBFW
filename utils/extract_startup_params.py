#!/usr/bin/env python3
# extract _estack and IVT from BBFW based the STM32 startup code
#
# example of a startup file: <STM32Cube install dir>/Repository/STM32Cube_FW_F4_V1.27.1/Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f427xx.s

import getopt
import struct
import re
import sys


def is_BL(hw0, hw1):
    return hw0 & 0xf800 == 0xf000 and hw1 & 0xd000 == 0xd000

def decode_BL(hw0, hw1, addr):
    # see Armv7-M Architecture Reference Manual (DDI0403E) - A7.7.18 (A7-213)
    s = (hw0 & 0x0400) >> 10
    imm10 = hw0 & 0x03ff
    j1 = (hw1 & 0x2000) >> 13
    j2 = (hw1 & 0x0800) >> 11
    imm11 = hw1 & 0x07ff
    i1 = ~(j1 ^ s) & 0x1
    i2 = ~(j2 ^ s) & 0x1
    offset = i1 << 23 | i2 << 22 | imm10 << 12 | imm11 << 1
    if s == 1:
        offset = -1 - (offset ^ 0x00ffffff)
    new_addr = addr + offset + 4
    return new_addr


base_address = 0x08020000
startup_file = 'startup_stm32f4xxxx.s'
radare2 = False
opts, args = getopt.getopt(sys.argv[1:], 'b:s:r')
for o, a in opts:
    if o == '-b':
        base_address = int(a, 0)
    elif o == '-s':
        startup_file = a
    elif o == '-r':
        radare2 = True

filename = args[0]
with open(filename, 'rb') as f:
    fw = f.read()

end_address = base_address + len(fw)

reset_handler = None
default_handler = None

if radare2:
    print('# load the image')
    print(f'f _base = 0x{base_address:08x}')
    print(f'o {filename} _base rx')
    print(f'omn _base flash')
    print()
    print('# IVT functions')
    print('fs symbols')
else:
    print(f'_base\t{base_address:08x}')

parse_line = re.compile(r'\s+(\.\S+)\s+(\S+)')
skip_line = True
fw_pos = 0
with open(startup_file, 'r') as f:
    for line in f:
        line = line.rstrip()
        if skip_line or not line:
            if line == 'g_pfnVectors:':
                skip_line = False
            continue
        m = parse_line.match(line)
        if not m:
            continue
        type = m.group(1)
        name = m.group(2)
        if type == '.word':
            value = struct.unpack('<I', fw[fw_pos:fw_pos+4])[0]
            if name == '0':
                if value not in [0x0, default_handler]:
                    print(f'unexpected non-zero value at position {fw_pos}: {value:08x}', file=sys.stderr)
            else:
                address = value & ~0x1
                if address >= base_address and address < end_address:
                    fw_pos1 = address - base_address
                    instr = struct.unpack('<H', fw[fw_pos1:fw_pos1+2])[0]
                    if instr == 0xe7fe:   # while(1) {} -> Default_Handler
                        default_handler = value
                if value != default_handler:
                    if radare2:
                        if name != '_estack':
                            print(f'f sym.{name} = 0x{address:08x}')
                    else:
                        print(f'{name}\t{value:08x}')
                if name == 'Reset_Handler':
                    reset_handler = value
            fw_pos += 4

if default_handler is not None:
    if radare2:
        address = default_handler & ~0x1
        print(f'f sym.Default_Handler = 0x{address:08x}')
    else:
        print(f'Default_Handler\t{default_handler:08x}')

if radare2:
    print()
    print('# useful memory addresses')
    print('fs *')

# extract some more information from Reset_Handler
if reset_handler is not None:
    address = reset_handler & ~0x1
    fw_pos = address - base_address
    # look for the end of Reset_Handler
    while fw_pos < end_address - base_address:
        instr = struct.unpack('<H', fw[fw_pos:fw_pos+2])[0]
        if instr == 0xe7fe:   # while(1) {} -> end of Reset_Handler
            break
        fw_pos += 2
    # save the previous six instructions to see if they are BLs to well known
    # functions
    pinstrs_pos = fw_pos - 12
    pinstrs = struct.unpack('<HHHHHH', fw[pinstrs_pos:pinstrs_pos+12])
    # align address to word boundary
    if fw_pos % 4 == 2:
        fw_pos += 2
    for name in ['_estack', '_sdata', '_edata', '_sidata', '_sbss', '_ebss']:
        value = struct.unpack('<I', fw[fw_pos:fw_pos+4])[0]
        if radare2:
            print(f'f {name} = 0x{value:08x}')
        else:
            print(f'{name}\t{value:08x}')
        fw_pos += 4
    # check if the previous six instructions in Reset_handler are BLs
    if (is_BL(pinstrs[0], pinstrs[1]) and is_BL(pinstrs[2], pinstrs[3]) and
        is_BL(pinstrs[4], pinstrs[5])):
        bl_address = base_address + pinstrs_pos
        system_init_address = decode_BL(pinstrs[0], pinstrs[1], bl_address)
        libc_init_array_address = decode_BL(pinstrs[2], pinstrs[3], bl_address + 4)
        main_address = decode_BL(pinstrs[4], pinstrs[5], bl_address + 8)
        if radare2:
            print()
            print('# more functions from Reset_Handler')
            print('fs symbols')
            print(f'f sym.SystemInit = 0x{system_init_address:08x}')
            print(f'f sym.__libc_init_array = 0x{libc_init_array_address:08x}')
            print(f'f sym.main = 0x{main_address:08x}')
        else:
            # set the last bit to 1 for Thumb instructions
            print(f'SystemInit\t{system_init_address | 0x1:08x}')
            print(f'__libc_init_array\t{libc_init_array_address | 0x1:08x}')
            print(f'main\t{main_address | 0x1:08x}')

if radare2:
    print()
    print(f's _base')
