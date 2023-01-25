#!/usr/bin/env python3
# extract _estack and IVT from BBFW based the STM32 startup code
#
# example of a startup file: <STM32Cube install dir>/Repository/STM32Cube_FW_F4_V1.27.1/Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f427xx.s

import getopt
import struct
import re
import sys


base_address = 0x08020000
startup_file = 'startup_stm32f4xxxx.s'
opts, args = getopt.getopt(sys.argv[1:], 'b:s:')
for o, a in opts:
    if o == '-b':
        base_address = int(a, 0)
    elif o == '-s':
        startup_file = a

with open(args[0], 'rb') as f:
    fw = f.read()

end_address = base_address + len(fw)

reset_handler = None
default_handler = None

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
                    instr = struct.unpack('>H', fw[fw_pos1:fw_pos1+2])[0]
                    if instr == 0xfee7:   # while(1) {} -> Default_Handler
                        default_handler = value
                if value != default_handler:
                    print(f'{name}\t{value:08x}')
                if name == 'Reset_Handler':
                    reset_handler = value
            fw_pos += 4

if default_handler is not None:
    print(f'Default_Handler\t{default_handler:08x}')

# extract some more information from Reset_Handler
if reset_handler is not None:
    address = reset_handler & ~0x1
    fw_pos = address - base_address
    # look for the end of Reset_Handler
    while fw_pos < end_address - base_address:
        instr = struct.unpack('>H', fw[fw_pos:fw_pos+2])[0]
        fw_pos += 2
        if instr == 0xfee7:   # while(1) {} -> end of Reset_Handler
            break
    # align address to word boundary
    if fw_pos % 4 == 2:
        fw_pos += 2
    for name in ['_estack', '_sdata', '_edata', '_sidata', '_sbss', '_ebss']:
        value = struct.unpack('<I', fw[fw_pos:fw_pos+4])[0]
        print(f'{name}\t{value:08x}')
        fw_pos += 4
