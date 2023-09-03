# Assign function names and types based on their address or their FunctionID (hash)
#@author Franco Venturi fventuri@comcast.net
#@category Analysis
#@keybinding
#@menupath
#@toolbar

# License: GPLv3

# Python 2.7.3 (argh!)

from __future__ import print_function
import os
import re

from java.io import File
from generic.hash import FNV1a64MessageDigestFactory
from ghidra.feature.fid.hash import FunctionBodyFunctionExtentGenerator
from ghidra.feature.fid.hash import MessageDigestFidHasher
from ghidra.feature.fid.service import FidService
from ghidra.program.model.data import DataTypePath
#from ghidra.program.model.data import Pointer
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import VariableStorage
from ghidra.program.model.symbol import SourceType
from ghidra.util import Msg


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

msg_originator = getScriptName().split('.')[-2]


def build_config():
    for arg in getScriptArgs():
        if '=' in arg:
            key, value = arg.split('=', 1)
            config[key.strip()] = value.strip()
        else:
            config[arg.strip()] = 'True'
    for key in propertiesFileParams.keySet():
        if key not in config:
            config[key] = propertiesFileParams.getValue(key)


def get_boolean(property_name):
    if property_name not in config:
        return False
    property = config[property_name].lower()
    if property in ['true', 'yes', 'on', 'enable', 'enabled']:
        return True
    elif property in ['false', 'no', 'off', 'disable', 'disabled']:
        return False
    else:
        Msg.warn('invalid value "{}" for boolean property {}'.format(config[property_name], property_name))
        return None


dtmgrs = dict()

def load_gdt_archives():
    gdt_archives = [x.strip() for x in config['gdt_archives'].split(',')]
    for gdt_archive in gdt_archives:
        key = os.path.splitext(os.path.basename(gdt_archive))[0]
        dtmgrs[key] = openDataTypeArchive(File(gdt_archive), True)


functions_by_address = dict()
functions_by_name = dict()
functions_by_full_hash = dict()
functions_by_specific_hash = dict()

def build_program_functions_dicts():
    fid_service = FidService()
    short_functions_generator = FunctionBodyFunctionExtentGenerator()
    short_functions_digest_factory = FNV1a64MessageDigestFactory()
    short_functions_hasher = MessageDigestFidHasher(short_functions_generator, 1, short_functions_digest_factory, list());
    function = getFirstFunction()
    while True:
        name = function.getName()
        entry_point = function.getEntryPoint().getOffset()
        if name not in functions_by_name:
            functions_by_name[name] = entry_point
        else:
            print('*** ERROR: duplicate function name:', name, file=sys.stderr)
        hash_function = fid_service.hashFunction(function)
        if hash_function is not None:
            full_hash = hash_function.getFullHash()
            if full_hash < 0:
                full_hash += 0x10000000000000000
            specific_hash = hash_function.getSpecificHash()
            if specific_hash < 0:
                specific_hash += 0x10000000000000000
            functions_by_address[entry_point] = (name, full_hash, specific_hash, None)
            functions_by_full_hash[full_hash] = entry_point
            functions_by_specific_hash[specific_hash] = entry_point
        else:
            functions_by_address[entry_point] = (name, None, None, None)
        function = getFunctionAfter(function)
        if function is None:
            break

    # for short functions with no hashes find closest reference function
    look_behind = dict()
    last_reference = None
    for address, function_info in sorted(functions_by_address.items()):
        if function_info[1] is not None:
            last_reference = address
        else:
            if last_reference is not None:
                look_behind[address] = last_reference
            else:
                look_behind[address] = None
    look_ahead = dict()
    last_reference = None
    for address, function_info in sorted(functions_by_address.items(), reverse=True):
        if function_info[1] is not None:
            last_reference = address
        else:
            if last_reference is not None:
                look_ahead[address] = last_reference
            else:
                look_ahead[address] = None
    for address in functions_by_address:
        name, full_hash, _, _ = functions_by_address[address]
        if full_hash is not None:
            continue
        if look_behind[address] is None:
            reference_address = look_ahead[address]
        elif look_ahead[address] is None:
            reference_address = look_behind[address]
        elif address - look_behind[address] <= look_ahead[address] - address:
            reference_address = look_behind[address]
        else:
            reference_address = look_ahead[address]
        function = getFunctionAt(toAddr(address))
        hash_function = short_functions_hasher.hash(function)
        specific_hash = hash_function.getSpecificHash()
        if specific_hash < 0:
            specific_hash += 0x10000000000000000
        functions_by_address[address] = (name, None, specific_hash, reference_address)
        ### fv
        ###full_hash = hash_function.getFullHash()
        ###if full_hash < 0:
        ###    full_hash += 0x10000000000000000
        ###print('SHORT FUNCTION: 0x{:08x} -> 0x{:08x} {} 0x{:x} [0x{:x}/0x{:x}]'.format(address, reference_address, '+' if address >= reference_address else '-', abs(address - reference_address), full_hash, specific_hash))


function_offset_re = re.compile(r'([^+\-\s]+)\s*([+-])\s*([0-9a-fA-Fx]+)')

def find_matching_function(fields):
    address = int(fields['address'], 0) if fields['address'] else None
    full_hash = None
    address_from_reference = None
    fhfo = fields['full hash/reference']
    if fhfo:
        try:
            full_hash = int(fhfo, 0)
        except ValueError:
            m = function_offset_re.match(fhfo)
            if m:
                base_function_name = m.group(1)
                functions = getGlobalFunctions(base_function_name)
                if len(functions) == 0:
                    Msg.warn(msg_originator, "Unable to find reference function '{}'".format(base_function_name))
                elif len(functions) > 1:
                    Msg.warn(msg_originator, "Found multiple reference functions '{}'".format(base_function_name))
                else:
                    address_from_reference = functions[0].getEntryPoint().getOffset()
                    offset = int(m.group(3), 0)
                    if m.group(2) == '+':
                        address_from_reference += offset
                    elif m.group(2) == '-':
                        address_from_reference -= offset
            else:
                Msg.warn(msg_originator, 'Invalid function reference field: {}'.format(fhfo))
    #### fv
    ###print('FUNCTION: ', fields['name'], '- full hash:', full_hash, '- address_from_reference:', address_from_reference)

    specific_hash = int(fields['specific hash'], 0) if fields['specific hash'] else None

    if address is not None and address in functions_by_address:
        name_from_address, full_hash_from_address, specific_hash_from_address, reference_from_address = functions_by_address[address]

        # case 1 - match on address + full_hash + specific_hash
        if full_hash_from_address is not None:
            if full_hash == full_hash_from_address and specific_hash == specific_hash_from_address:
                # strong match
                Msg.info(msg_originator, 'strong match (functionId) - name={} address=0x{:08x}'.format(fields['name'], address))
                return (address, name_from_address, full_hash_from_address, specific_hash_from_address, None)

        # case 2 - match on address + reference + specific_hash
        if reference_from_address is not None:
            if address_from_reference == address and specific_hash == specific_hash_from_address:
                # strong match
                Msg.info(msg_originator, 'strong match (reference function) - name={} address=0x{:08x}'.format(fields['name'], address))
                return (address, name_from_address, None, specific_hash_from_address, reference_from_address)

    else:
        # case 3 - match on full_hash + specific_hash
        if full_hash is not None and specific_hash in functions_by_specific_hash:
            address = functions_by_specific_hash[specific_hash]
            name_from_address, full_hash_from_address, specific_hash_from_address, reference_from_address = functions_by_address[address]
            if full_hash == full_hash_from_address and specific_hash == specific_hash_from_address:
                # weak match
                Msg.info(msg_originator, 'weak match (functionId) - name={} address=0x{:08x}'.format(fields['name'], address))
                return (address, name_from_address, full_hash_from_address, specific_hash_from_address, None)

        # case 4 - match on reference + specific_hash
        if address_from_reference is not None and address_from_reference in functions_by_address:
            address = address_from_reference
            name_from_address, full_hash_from_address, specific_hash_from_address, reference_from_address = functions_by_address[address]
            if address_from_reference == address and specific_hash == specific_hash_from_address:
                # weak match
                Msg.info(msg_originator, 'weak match (reference function) - name={} address=0x{:08x}'.format(fields['name'], address))
                return (address, name_from_address, None, specific_hash_from_address, reference_from_address)

    if address is not None and address in functions_by_address:
        name_from_address, full_hash_from_address, specific_hash_from_address, reference_from_address = functions_by_address[address]

        # case 5 - match on address only
        if full_hash is None and specific_hash is None and (address_from_reference is None or address_from_reference == address):
            # weak match
            Msg.info(msg_originator, 'weak match (address only) - name={} address=0x{:08x}'.format(fields['name'], address))
            return (address, name_from_address, full_hash_from_address, specific_hash_from_address, reference_from_address)

    else:
        # case 6a - match on full_hash or specific_hash only (specific hash case)
        if full_hash is not None and specific_hash in functions_by_specific_hash:
            address = functions_by_specific_hash[specific_hash]
            name_from_address, full_hash_from_address, specific_hash_from_address, reference_from_address = functions_by_address[address]
            # very weak match
            Msg.info(msg_originator, 'very weak match (specific hash only) - name={} address=0x{:08x}'.format(fields['name'], address))
            return (address, name_from_address, full_hash_from_address, specific_hash_from_address, None)

        # case 6b - match on full_hash or specific_hash only (full hash case)
        if full_hash is not None and full_hash in functions_by_full_hash:
            address = functions_by_full_hash[full_hash]
            name_from_address, full_hash_from_address, specific_hash_from_address, reference_from_address = functions_by_address[address]
            # very weak match
            Msg.info(msg_originator, 'very weak match (full hash only) - name={} address=0x{:08x}'.format(fields['name'], address))
            return (address, name_from_address, full_hash_from_address, specific_hash_from_address, None)

    # can't find any kind of match
    return None


column_names_re = re.compile(r'#(?:\s*\w[^,]+,){5}')

def assign_functions(functions_file):
    column_names = None
    maxsplit = 0
    output_functions = get_boolean('output_functions')
    if output_functions:
        functions_file_extparts = os.path.splitext(functions_file)
        program_name = currentProgram.getName()
        output_functions_file = functions_file_extparts[0] + '-' + os.path.splitext(program_name)[0] + functions_file_extparts[1]
        fout = open(output_functions_file, 'w')
    append_suffix = get_boolean('append_suffix')
    fin = open(functions_file)
    for line in fin:
        if line.strip() == '':
            if output_functions:
                fout.write(line)
            continue
        if line.startswith('#'):
            if column_names is None and column_names_re.match(line):
                column_names = [x.strip() for x in line[1:].split(',')]
                maxsplit = len(column_names) - 1
                if output_functions:
                    column_idxs = {name: idx for idx, name in enumerate(column_names)}
            if output_functions:
                fout.write(line)
            continue
        fields_by_order = [x.strip() for x in line.split(',', maxsplit)]
        #fields_by_order = [x if x != '-' else '' for x in fields_by_order]
        fields_by_name = {k: v for k, v in zip(column_names, fields_by_order)}
        matching_function = find_matching_function(fields_by_name)
        if matching_function is None:
            Msg.warn(msg_originator, "Unable to find a function matching '{}'". format(fields_by_name['name']))
            if output_functions:
                fout.write(line)
            continue
        address, current_name, full_hash, specific_hash, reference_address = matching_function
        fields_by_name['address'] = '0x{:08x}'.format(address)
        if full_hash is not None:
            fields_by_name['full hash/reference'] = '0x{:x}'.format(full_hash)
        elif reference_address is not None:
            reference_function = getFunctionAt(toAddr(reference_address))
            reference_function_name = reference_function.getName()
            offset = address - reference_address
            fields_by_name['full hash/reference'] = '{}{}0x{:x}'.format(reference_function_name, '+' if offset >= 0 else '-', abs(offset))
        else:
            fields_by_name['full hash/reference'] = ''
        if specific_hash is not None:
            fields_by_name['specific hash'] = '0x{:x}'.format(specific_hash)
        else:
            fields_by_name['specific hash'] = ''
        if output_functions:
            unstripped_fields = [x for x in line.split(',', maxsplit)]
            unstripped_fields[column_idxs['address']] = fields_by_name['address']
            unstripped_fields[column_idxs['full hash/reference']] = fields_by_name['full hash/reference']
            unstripped_fields[column_idxs['specific hash']] = fields_by_name['specific hash']
            fout.write(','.join(unstripped_fields))
        name = fields_by_name['name']
        ###Msg.info(msg_originator, '{}@0x{:08x} -> {}'.format(current_name, address, name))
        func = getFunctionAt(toAddr(address))
        source = SourceType.USER_DEFINED
        if append_suffix:
            name = '_'.join((name, fields_by_name['suffix']))
        func.setName(name, source)
        if fields_by_name['gdt']:
            type = dtmgrs[fields_by_name['gdt']].getDataType(DataTypePath('/functions', name))
            func.setCallingConvention(type.getCallingConventionName())
            func.setComment(type.getComment())
            params = list()
            for arg in type.getArguments():
                arg_name = arg.getName()
                arg_type = arg.getDataType()
                #if isinstance(arg_type, Pointer):
                #    clone_type = Pointer(arg_type.getDataType().getClone())
                #else:
                #    clone_type = arg_type.getClone()
                param = ParameterImpl(arg_name, arg_type, VariableStorage.UNASSIGNED_STORAGE, currentProgram)
                params.append(param)
            func.replaceParameters(params, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, False, source)
            func.setReturnType(type.getReturnType(), source);
            func.setVarArgs(type.hasVarArgs());
            func.setNoReturn(type.hasNoReturn());
            func.setSignatureSource(source);
        # build plate comment
        comment_lines = list()
        for column_name in column_names:
             value = fields_by_name[column_name]
             if not value:
                 continue
             value = value.replace('\\n', '\n' + ' ' * (len(column_name) + 2))
             comment_lines.append('{}: {}'.format(column_name.capitalize(), value))
        setPlateComment(toAddr(address), '\n'.join(comment_lines))
    fin.close()
    if output_functions:
        fout.close()


def main():

    build_config()

    load_gdt_archives()

    build_program_functions_dicts()

    functions_files = [x.strip() for x in config['functions'].split(',')]
    for functions_file in functions_files:
        assign_functions(functions_file)

    if logprint.log_file:
        logprint.log_file.close()


if __name__ == '__main__':
    main()
