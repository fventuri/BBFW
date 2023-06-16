# Parses STM Standard Peripheral Library header files and extracts the following info:
# - structures
# - enumerationsi
# - typedefs
# - memory locations
# - peripherals
# - interrupt vector table and interrupt handler functions
#@author Franco Venturi fventuri@comcast.net
#@category Data Types
#@keybinding
#@menupath
#@toolbar

# License: GPLv3

# Python 2.7.3 (argh!)

from __future__ import print_function
import os
import re
import subprocess
import threading

from java.io import File
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import *


config = dict()

# logging
#log_file = None
log_file = '/tmp/{}.log'.format(re.sub('.py$', '', sourceFile.getName()))

def logprint(*args):
    logprint.log_messages += 1
    if logprint.log_file:
        print(*args, file=logprint.log_file)
logprint.log_file = open(log_file, 'w') if log_file else None
logprint.log_messages = 0


def build_config():
    for arg in getScriptArgs():
        key, value = arg.split('=', 1)
        config[key.strip()] = value.strip()
    for key in propertiesFileParams.keySet():
        if key not in config:
            config[key] = propertiesFileParams.getValue(key)


def add_basic_data_types(dtmgr):
    print('Adding basic data types')
    tran_id = dtmgr.startTransaction('Add basic types')

    # add fundamental types
    dtmgr.addDataType(TypedefDataType('int8_t', SignedCharDataType()), None)
    dtmgr.addDataType(TypedefDataType('int16_t', SignedWordDataType()), None)
    dtmgr.addDataType(TypedefDataType('int32_t', SignedDWordDataType()), None)
    dtmgr.addDataType(TypedefDataType('int64_t', SignedQWordDataType()), None)
    dtmgr.addDataType(TypedefDataType('uint8_t', UnsignedCharDataType()), None)
    dtmgr.addDataType(TypedefDataType('uint16_t', WordDataType()), None)
    dtmgr.addDataType(TypedefDataType('uint32_t', DWordDataType()), None)
    dtmgr.addDataType(TypedefDataType('uint64_t', QWordDataType()), None)

    dtmgr.endTransaction(tran_id, True)


def run_c_preprocessor():
    include_prefix = '-I' + config['spl_install_dir'] + '/'
    cpp_command = ['gcc', '-E', '-C', '-dD', '-DUSE_STDPERIPH_DRIVER',
                   '-D' + config['mcu_variant'],
                   include_prefix + 'Libraries/CMSIS/Device/ST/STM32F4xx/Include',
                   include_prefix + 'Libraries/STM32F4xx_StdPeriph_Driver/inc',
                   include_prefix + 'Libraries/CMSIS/Include',
                   include_prefix + 'Project/STM32F4xx_StdPeriph_Templates',
                   '-U__GNUC__',
                   '-D__STATIC_INLINE=static inline',
                   '-']
    #logprint('cpp_command', cpp_command)

    cpp = subprocess.Popen(cpp_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
    cpp.stdin.write('#include <stm32f4xx.h>\n')
    cpp.stdin.close()
    return cpp


base_addresses = dict()

base_address_case1_re = re.compile(r'^\((?:\(uint32_t ?\))?(0x[0-9A-Fa-f]+)(?:UL|U)?\)$')
base_address_case2_re = re.compile(r'^\(([A-Za-z0-9_]+_BASE) \+ (0x[0-9A-Fa-f]+)(?:UL|U)?\)$')
base_address_case3_re = re.compile(r'^\(?([A-Za-z0-9_]+_BASE)\)?$')

def parse_base_addresses(key, value):
    global base_addresses
    if not key.endswith('_BASE'):
        return False
    m = base_address_case1_re.match(value)
    if m:
        base_addresses[key] = int(m.group(1), 0)
        return True
    m = base_address_case2_re.match(value)
    if m:
        base_addresses[key] = base_addresses[m.group(1)] + int(m.group(2), 0)
        return True
    m = base_address_case3_re.match(value)
    if m:
        base_addresses[key] = base_addresses[m.group(1)]
        return True
    return False


peripherals = dict()

peripheral_re = re.compile(r'^\(\s*\(\s*([^\s*]+)\s*\*\s*\)\s*([A-Za-z0-9_]+_BASE)\s*\)$')

def parse_peripherals(key, value):
    global peripherals
    m = peripheral_re.match(value)
    if m:
        peripheral_type = m.group(1)
        peripheral_address = base_addresses[m.group(2)]
        peripherals[key] = (peripheral_type, peripheral_address)
        return True
    return False


typed_values = dict()

typed_value_re = re.compile(r'^\(\s*\(\s*([^\s)]+)\s*\)\s*([0-9]+|0x[0-9A-Fa-f]+)U?\s*\)$')
typed_value_re = re.compile(r'^\(\s*\(\s*([^\s)]+)\s*\)\s*(.+)\s*\)$')

precomputed_expressions = {
    '0x20000000U': 0x20000000,
    '0x00000000 << 3': 0x00000000,
    '0x00000001 << 3': 0x00000008,
    '0x00000002 << 3': 0x00000010,
    '0x00000003 << 3': 0x00000018,
    '0x00000004 << 3': 0x00000020,
    '0x00000005 << 3': 0x00000028,
    '(PWR_CR_LPDS | PWR_CR_LPUDS)': 0x00000401,
    '!CAN_ModeStatus_Failed': 0x01,
    'SAI_xFRCR_FSPO': 0x00020000,
}

def parse_typed_values(key, value):
    global typed_values
    m = typed_value_re.match(value)
    if not m:
        return False
    type = m.group(1)
    expression = m.group(2)

    # 1. try evaluating the expression as just an int constant
    try:
        evaluated = int(expression, 0)
    except ValueError:
        evaluated = None
    # 2. lookup existing typed values
    if evaluated is None:
        if expression in typed_values:
            evaluated = typed_values[expression][1]
    # 3. use precomputed values
    if evaluated is None:
        evaluated = precomputed_expressions.get(expression, None)

    if evaluated is not None:
        typed_values[key] = (type, evaluated)
    else:
        logprint('unable to evaluate expression::', expression)
    return True


# simple aliases key = value
def parse_aliases(key, value):
    if value not in typed_values:
        return False
    typed_values[key] = typed_values[value]
    return True


define_re = re.compile(r'^#define\s+(\S+)(?:\s+(.*))?')

def parse_defines(line):
    m = define_re.match(line)
    if not m:
        return False
    key = m.group(1).strip()
    value = m.group(2).strip()
    # skip define's with variables
    if '(' in key:
        pass
    elif parse_base_addresses(key, value):
        pass
    elif parse_peripherals(key, value):
        pass
    elif parse_typed_values(key, value):
        pass
    elif parse_aliases(key, value):
        pass
    else:
        logprint('ignoring define ' + line.rstrip('\n'))
    return True


structures = dict()

structure_fields = None
structure_field_comment = None

structure_start_re = re.compile(r'^\s*typedef +struct')
structure_end_re = re.compile(r'\s*} *(\S+) *;');
structure_field_re = re.compile(r'^\s*(.+)\s+([^\s\[]+)(?:\[(\d+)\])?\s*;')

structure_line_comment_re = re.compile(r'.*/\*!<(.*)\*/')
structure_multiline_comment_start_re = re.compile(r'.*/\*!<(.*)')
structure_multiline_comment_end_re = re.compile(r'(.*)\*/')

def parse_structures(line):
    global structures
    global structure_fields
    global structure_field_comment
    if structure_field_comment is not None:
        m = structure_multiline_comment_end_re.match(line)
        if m:
            structure_field_comment.append(m.group(1).strip())
            field_type, field_name, field_cardinality, field_comment = structure_fields[-1]
            field_comment = ' '.join(structure_field_comment)
            # remove multiple consecutive spaces in comments
            field_comment = ' '.join(field_comment.split())
            structure_field_comment = None
            structure_fields[-1] = (field_type, field_name, field_cardinality, field_comment)
        else:
            structure_field_comment.append(line.strip())
        return True
    if structure_start_re.match(line):
        structure_fields = list()
        return True
    if structure_fields is not None:
        m = structure_end_re.match(line)
        if m:
            structure_name = m.group(1)
            structures[structure_name] = structure_fields
            structure_fields = None
            return True
        m = structure_field_re.match(line)
        if m:
            field_type = m.group(1)
            # remove 'volatile' and 'volatile const'
            field_type = re.sub(r'^volatile(?: const)? ', '', field_type)
            field_name = m.group(2)
            field_cardinality = m.group(3)
            field_comment = None
            m = structure_line_comment_re.match(line)
            if m:
                field_comment = m.group(1).strip()
                # remove multiple consecutive spaces in comments
                field_comment = ' '.join(field_comment.split())
            structure_fields.append((field_type, field_name, field_cardinality,
                field_comment if field_comment is not None else ''))
            if field_comment is None:
                m = structure_multiline_comment_start_re.match(line)
                if m:
                    structure_field_comment = [m.group(1).strip()]
            return True
    return False


def intermediate_processor(input, output, spl_install_dir):
    file_line_name_re = re.compile(r'^# (\d+) "([^"]+)"(?: (\d+))?')
    in_spl_headers = False
    for line in input:
        m = file_line_name_re.match(line)
        if m:
            in_spl_headers = m.group(2).startswith(spl_install_dir)
            continue
        if not in_spl_headers:
            continue
        if parse_defines(line):
            pass
        else:
            parse_structures(line)
            #logprint.log_file.write(line)
            output.write(line)
    input.close()
    output.close()


def run_intermediate_processor(cpp):
    rfd, wfd = os.pipe()
    input = cpp.stdout
    output = os.fdopen(wfd, 'w')
    processor_thread = threading.Thread(target=intermediate_processor,
        args=(input, output, config['spl_install_dir']))
    processor_thread.start()
    return processor_thread, os.fdopen(rfd)


def run_c_parser(cin, dtmgr):
    print('Adding', config['mcu_variant'], 'data types')
    cparser = CParser(dtmgr, True, [])
    cparser.parse(cin)
    print('C parser messages:', cparser.getParseMessages())


def add_base_addresses(dtmgr):
    print('Adding base addresses')
    tran_id = dtmgr.startTransaction('Add base addresses')
    address_size = 4    # 32 bit MCU
    enum = EnumDataType('_BASE_ADDRESSES_', address_size)
    for key, value in sorted(base_addresses.items()):
        enum.add(key, value)
    dtmgr.addDataType(enum, None)
    dtmgr.endTransaction(tran_id, True)


def truncate_structure(original_structure, max_length):
    # remove (or shorten) fields from the tail until the length is less than
    # or equal to max_length
    dtmgr = original_structure.getDataTypeManager()
    truncated_structure = original_structure.copy(dtmgr)
    truncated_structure.setName(truncated_structure.getName() + '_Truncated')
    for idx in range(truncated_structure.getNumComponents()-1, -1, -1):
        excess_length = truncated_structure.getLength() - max_length
        if excess_length <= 0:
            break
        component = truncated_structure.getComponent(idx)
        component_length = component.getLength()
        if component_length <= excess_length:
            truncated_structure.delete(idx)
        else:
            datatype = component.getDataType()
            if isinstance(datatype, Array):
                element_length = datatype.getElementLength()
                # I am not sure if the next line takes into account alignment
                num_elements = int((max_length - component.getOffset()) / element_length)
                if num_elements > 0:
                    truncated_array = ArrayDataType(datatype.getDataType(), num_elements, element_length)
                    truncated_array.setCategoryPath(datatype.getCategoryPath())
                    truncated_array.setName(datatype.getName() + '_truncated_to_{}'.format(num_elements))
                    dtmgr.addDataType(truncated_array, None)
                    new_component_length = truncated_array.getLength()
                    new_component_name = component.getFieldName() + '_Truncated'
                    truncated_structure.replace(idx, truncated_array, new_component_length, new_component_name, 'TRUNCATED')
                else:
                    truncated_structure.delete(idx)
            else:
                truncated_structure.delete(idx)
    dtmgr.addDataType(truncated_structure, None)
    return truncated_structure.getName()


def add_peripherals(dtmgr):
    print('Adding peripherals')
    sorted_peripherals = sorted(peripherals.items(), key=lambda x: x[1][1])
    tran_id = dtmgr.startTransaction('Add peripherals')
    address_size = 4    # 32 bit MCU
    enum = EnumDataType('_PERIPHERALS_', address_size)
    for idx, (key, value) in enumerate(sorted_peripherals):
        typename = value[0]
        if idx < len(sorted_peripherals) - 1:
            type = dtmgr.getDataType(DataTypePath('/', typename))
            length = type.getLength()
            next_peripheral = sorted_peripherals[idx+1]
            max_length = next_peripheral[1][1] - value[1]
            if length > max_length:
                # create truncated type for peripherals that overlap in memory
                logprint('WARNING - Truncating peripheral {} length to {} bytes (instead of {} bytes) because it overlaps with peripheral {}'.format(key, max_length, length, next_peripheral[0]))
                typename = truncate_structure(type, max_length)
        enum.add(key, value[1], 'type=' + typename)
    dtmgr.addDataType(enum, None)
    dtmgr.endTransaction(tran_id, True)


def add_typed_values_enums(dtmgr):
    print('Adding typed values enums')
    type_lengths = {'uint8_t': 1, 'uint16_t': 2, 'uint32_t': 4}
    enums = dict()
    for key, value in typed_values.items():
        enum_name = '_'.join(key.split('_')[:-1])
        item_type = value[0]
        item_value = value[1]
        # case when the typed value doesn't have any '_' in its name
        if not enum_name:
            enum_name = key
        if enum_name not in enums:
            enums[enum_name] = (item_type, [(key, item_value)])
        else:
            enum_type, enum_values = enums[enum_name]
            if enum_type != item_type:
                logprint('INFO - inconsistent type in enum', enum_name, '- expected:', enum_type, 'found:', item_type)
                # select always the widest type
                if item_type == 'uint32_t':
                    if enum_type in ['uint8_t', 'uint16_t']:
                        enum_type = item_type
                elif item_type == 'uint16_t':
                    if enum_type in ['uint8_t']:
                        enum_type = item_type
            enum_values.append((key, item_value))
            enums[enum_name] = (enum_type, enum_values)

    tran_id = dtmgr.startTransaction('Add typed values enums')
    for key, (enum_type, enum_values) in sorted(enums.items()):
        enum = EnumDataType(key, type_lengths[enum_type])
        for item_name, item_value in sorted(enum_values):
            enum.add(item_name, item_value)
        dtmgr.addDataType(enum, None)
    dtmgr.endTransaction(tran_id, True)


def add_comments_to_structures(dtmgr):
    tran_id = dtmgr.startTransaction('Add comments to structures')
    for structure in dtmgr.getAllStructures():
        name = structure.getName()
        # remove the '_Truncated' suffix if present
        name = re.sub('_Truncated$', '', name)
        if name not in structures:
            continue
        fields = structures[name]
        numComponents = structure.getNumComponents()
        for idx in range(numComponents):
            component = structure.getComponent(idx)
            field_name = component.getFieldName()
            field = next((f for f in fields if f[1] == field_name), None)
            if field is not None:
                current_comment = component.getComment()
                if current_comment is not None:
                    component.setComment('{} - {}'.format(field[3], current_comment))
                else:
                    component.setComment(field[3])
    dtmgr.endTransaction(tran_id, True)


interrupt_vector_table_re = re.compile(r'^\s+\.word\s+(\S+)(?:\s+/\*\s+(.+)\s+\*/)?')

def add_interrupt_vector_table(dtmgr):
    startup_file = (config['spl_install_dir'] +
                    '/Libraries/CMSIS/Device/ST/STM32F4xx/Source/Templates/SW4STM32/startup_' +
                    config['mcu_variant'].lower() +
                    '.s')
    category = CategoryPath('/functions')
    f = open(startup_file)

    print('Adding interrupt vector table')
    tran_id = dtmgr.startTransaction('Add interrupt vector table')

    ivt = StructureDataType('ISRVector', 0)
    ivt.setPackingEnabled(True)

    reserved_count = 0
    reserved_length = 0

    in_interrupt_vector_table = False
    for line in f:
        if line.startswith('g_pfnVectors:'):
            in_interrupt_vector_table = True
            continue
        if not in_interrupt_vector_table:
            continue
        m = interrupt_vector_table_re.match(line)
        if not m:
            continue
        name = m.group(1)
        comment = m.group(2)
        if name == '0':
            reserved_length += 1
            continue
        if reserved_length > 0:
            reserved_count += 1
            undefined4 = Undefined4DataType()
            reserved = ArrayDataType(undefined4, reserved_length, undefined4.length)
            ivt.add(reserved, reserved.length, 'RESERVED{}'.format(reserved_count), None)
            reserved_length = 0
        if name == '_estack':
            ptr = PointerDataType(VoidDataType())
            ivt.add(ptr, ptr.length, name, comment)
        elif name.endswith('Handler'):
            func = FunctionDefinitionDataType(category, name)
            func.setCallingConvention("default");
            func.setComment(comment)
            func.setArguments([])
            func.setReturnType(VoidDataType())
            func.setVarArgs(False)
            # handlers are not expected to return
            func.setNoReturn(True)
            dtmgr.addDataType(func, None)
            ptr = PointerDataType(dtmgr.getDataType(DataTypePath(category, name)))
            ivt.add(ptr, ptr.length, name, comment)
        else:
            logprint('WARNING - unexpected field in interrupt vector table:', name)
    if reserved_length > 0:
        reserved_count += 1
        undefined4 = Undefined4DataType()
        reserved = ArrayDataType(undefined4, reserved_length, undefined4.length)
        ivt.add(reserved, reserved.length, 'RESERVED{}'.format(reserved_count), None)
        reserved_length = 0

    f.close()

    dtmgr.addDataType(ivt, None)

    func = FunctionDefinitionDataType(category, 'Default_Handler')
    func.setCallingConvention("default");
    func.setArguments([])
    func.setReturnType(VoidDataType())
    func.setVarArgs(False)
    # handlers are not expected to return
    func.setNoReturn(True)
    dtmgr.addDataType(func, None)

    dtmgr.endTransaction(tran_id, True)


def write_debug_info():
    dbgf = open(config['debug_file'], 'w')
    print('base_addresses:', file=dbgf)
    for k, v in sorted(base_addresses.items()):
        print('{}=0x{:08x}'.format(k, v), file=dbgf)
    print(file=dbgf)
    print('peripherals:', file=dbgf)
    for k, v in sorted(peripherals.items()):
        print('{}=0x{:08x} [{}]'.format(k, v[1], v[0]), file=dbgf)
    print(file=dbgf)
    print('typed values:', file=dbgf)
    for k, v in sorted(typed_values.items()):
        print('{}=0x{:08x} [{}]'.format(k, v[1], v[0]), file=dbgf)
    print(file=dbgf)
    print('structures:', file=dbgf)
    for k, v in sorted(structures.items()):
        print('{}: {}'.format(k, v), file=dbgf)
    print(file=dbgf)
    dbgf.close()


def main():

    build_config()

    archive_file = File(os.path.join(config['output_dir'],
                                     config['mcu_variant'] + '.gdt'))
    dtmgr = FileDataTypeManager.createFileArchive(archive_file)

    add_basic_data_types(dtmgr)

    cpp = run_c_preprocessor()
    processor_thread, cin = run_intermediate_processor(cpp)
    run_c_parser(cin, dtmgr)
    processor_thread.join()
    cpp_exit_status = cpp.wait()
    if cpp_exit_status != 0:
        print('WARNING - C preprocessor returned', cpp_exit_status)

    print('Summary:')
    print('    log messages:', logprint.log_messages)
    print('    base_addresses:', len(base_addresses))
    print('    peripherals:', len(peripherals))
    print('    typed values:', len(typed_values))
    print('    structures:', len(structures))
    if 'debug_file' in config:
        write_debug_info()

    add_base_addresses(dtmgr)
    add_peripherals(dtmgr)
    add_typed_values_enums(dtmgr)
    add_comments_to_structures(dtmgr)
    add_interrupt_vector_table(dtmgr)

    dtmgr.save()
    dtmgr.close()

    if logprint.log_file:
        logprint.log_file.close()


if __name__ == '__main__':
    main()
