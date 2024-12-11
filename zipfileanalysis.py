import binascii
import os
import zipfile
import file_signatures
import tempfile

# 파일 읽기
file_data = b''
broken_flag = 0

# 시그니처 선언
eocdr_signature = b'\x50\x4b\x05\x06'   # End of Central Directory Record (EOCDR)
cdfh_signature = b'\x50\x4b\x01\x02'    # Central directory file header (CDFH)
lfh_signature = b'\x50\x4b\x03\x04'     # Local File Header (LFH)

# 오프셋 및 데이터 저장 변수 선언
# broken일 경우(못 찾았을 경우) 오프셋과 데이터 모두 -1 값을 가짐
eocdr_offset = 0
cdfh_offsets = []
lfh_offsets = []

eocdr_data = b''
cdfh_datas = []
lfh_datas = []

eocdr_fields = []
cdfh_fields = []
lfh_fields = []

all_lfh_fields = []
all_cdfh_fields = []

# LFH에서 쓰이는 압축 방식
compression_methods = {
    0x00: "no compression",
    0x01: "shrunk",
    0x02: "reduced with compression factor 1",
    0x03: "reduced with compression factor 2",
    0x04: "reduced with compression factor 3",
    0x05: "reduced with compression factor 4",
    0x06: "imploded",
    0x07: "reserved",
    0x08: "deflated",
    0x09: "enhanced deflated",
    0x0A: "PKWare DCL imploded",
    0x0B: "reserved",
    0x0C: "compressed using BZIP2",
    0x0D: "reserved",
    0x0E: "LZMA",
    0x0F: "reserved",
    0x10: "reserved",
    0x11: "reserved",
    0x12: "compressed using IBM TERSE",
    0x13: "IBM LZ77 z",
    0x62: "PPMd version I, Rev 1"
}

# Version Required When Creating
version_required = {
    0x00: "MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)",
    0x01: "Amiga",
    0x02: "OpenVMS",
    0x03: "UNIX",
    0x04: "VM/CMS",
    0x05: "Atari ST",
    0x06: "OS/2 H.P.F.S.",
    0x07: "Macintosh",
    0x08: "Z-System",
    0x09: "CP/M",
    0x0A: "Windows NTFS",
    0x0B: "MVS (OS/390 - Z/OS)",
    0x0C: "VSE",
    0x0D: "Acorn Risc",
    0x0E: "VFAT",
    0x0F: "alternate MVS",
    0x10: "BeOS",
    0x11: "Tandem",
    0x12: "OS/400",
    0x13: "OS/X (Darwin)",
    # Values from 0x14 to 0xFF are also unused
}

# General purpose bit flag (GPB flag) 
gpb_flags = {
    0: "encrypted file",
    1: "compression option 1",
    2: "compression option 2",
    3: "data descriptor",
    4: "enhanced deflation",
    5: "compressed patched data",
    6: "strong encryption",
    11: "language encoding",
    13: "mask header values"
  }

internal_file_attributes = {
    0x00: "Apparent ASCII/text file",
    0x01: "Reserved",
    0x02: "Control Field Records Precede Logical Records",
    # Values from 0x03 to 0x10 are also unused
}

def calc_time(mod_time):
    mod_time = int.from_bytes(lfh_fields[4]["value"], "little")
    seconds = (mod_time & 0x1F) * 2         # 00-04 bit: seconds, 하위 5비트 추출. 2초 단위로 저장되어 있음
    minutes = (mod_time >> 5) & 0x3F        # 05-10 bit: minutes, 중간 6비트 추출
    hours = (mod_time >> 11) & 0x1F         # 11-15 bit: hours, 상위 5비트 추출
    return hours, minutes, seconds

def calc_date(ms_date):
    # yyyyyyy(7 bits) mmmm(4 bits) ddddd(5 bits) 총 16 bits
    ms_date = int.from_bytes(lfh_fields[5]["value"], "little")
    day = ms_date & 0x1F                    # 00-04 bit: day, 하위 5비트 추출. 
    month = (ms_date >> 5) & 0x0F           # 05-08 bit: month, 중간 4비트 추출
    year = ((ms_date >> 9) & 0x7F) + 1980   # 09-15 bit: year from 1980, 상위 7비트 추출
    return year, month, day

# 시그니처로 각 파트 위치 찾기 및 데이터 뽑아내기
def find_parts():
    try:
        global eocdr_offset, eocdr_data, cdfh_offsets, cdfh_datas, lfh_offsets, lfh_datas, broken_flag

        # EOCDR 위치 찾기(1개), 데이터 저장
        eocdr_offset = file_data.rfind(eocdr_signature)
        if eocdr_offset == -1:                      # EOCDR 시그니처를 찾지 못했을 경우
            broken_flag = 1
            eocdr_data = -1
            print("[!!]EOCDR signature not found.. This means that the ZIP file is corrupted.")           
        else:                                   
            eocdr_data = file_data[eocdr_offset:]
        #print(f"EOCDR offset: {eocdr_offset}")

        # cdfh 위치 찾기(파일 개수만큼)
        cdfh_offset = 0
        try_flag = 0
        while True:
            cdfh_offset = file_data.find(cdfh_signature, cdfh_offset)
            if cdfh_offset == -1: 
                if try_flag == 0: # 아예 cdfh 시그니처를 찾지 못했을 경우 - 정상적인 zip 파일이 아님
                    broken_flag = 1
                    cdfh_offsets, cdfh_datas = -1, -1
                    print("[!!]CDFH signature not found.. This means that the ZIP file is corrupted.")
                break
            cdfh_offsets.append(cdfh_offset)      
            cdfh_offset += len(cdfh_signature)
            try_flag += 1

        if cdfh_offsets != -1:
            for i in range(len(cdfh_offsets) - 1):
                cdfh_datas.append(file_data[cdfh_offsets[i]:cdfh_offsets[i + 1]])
            cdfh_datas.append(file_data[cdfh_offsets[-1]:eocdr_offset])    # EOCDR 시작 전까지
        #print(f"CDFH offsets: {cdfh_offsets}")

        # LFH 위치 찾기
        lfh_offset = 0
        try_flag = 0
        while True:
            lfh_offset = file_data.find(lfh_signature, lfh_offset)
            if lfh_offset == -1:
                if try_flag == 0: # 아예 시그니처를 찾지 못했을 경우 - 정상적인 zip 파일이 아님
                    broken_flag = 1
                    lfh_offsets, lfh_datas = -1, -1
                    print("[!!]LFH signature not found.. This means that the ZIP file is corrupted.")
                break
            lfh_offsets.append(lfh_offset)
            lfh_offset += len(lfh_signature)
            try_flag += 1

        if lfh_offsets != -1:
            for i in range(len(lfh_offsets) - 1):
                lfh_datas.append(file_data[lfh_offsets[i]:lfh_offsets[i + 1]])
            lfh_datas.append(file_data[lfh_offsets[-1]:cdfh_offsets[0]])  # cdfh 시작 전까지
        #print(f"LFH offsets: {lfh_offsets}")

    # 부서진 zip파일인 경우
    except ValueError as e:
        print(f"Warning: {e}. This ZIP file might be corrupted.")
                     
def hexdump():
    print('[*] Hex Dump of file:')

    # 헤더 출력
    print('\033[96mOffsef(h) 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f', end='')  # print the header
    print('  ', end='')
    print('Decoded text\033[0m')

    # 16바이트마다 한 줄씩 출력
    for line in range(0, len(file_data)//16+1):
        # 주소 출력
        print('\033[96m%08x: ' % (line*16), end='\033[0m')

        if broken_flag == 0: 
            # 실제 값들을 출력하는 부분
            for i in range(0, 16):
                index = (line * 16) + i
                if index < len(file_data):
                    # EOCDR 부분을 빨간색으로 표시
                    if eocdr_offset <= index < eocdr_offset + 22:
                        print('\033[91m%02x \033[0m' % file_data[index], end='')
                    elif cdfh_offsets[0] <= index < eocdr_offset:
                        # cdfh 부분을 노란색으로 표시
                        print('\033[93m%02x \033[0m' % file_data[index], end='')
                    elif lfh_offsets[0] <= index < cdfh_offsets[0]:
                        # LFH 부분을 초록색으로 표시
                        print('\033[92m%02x \033[0m' % file_data[index], end='')
                    else:
                        # 나머지 값들은 흰색으로 표시
                        val = file_data[index]
                        print('%02x ' % val, end='')
                else: # 값이 없으면 3칸의 공백 출력
                    print('   ', end='')
                    
            # ASCII 값을 출력하는 부분
            print(' ', end='')  # space between hex and ASCII
            for i in range(0, 16):
                index = (line * 16) + i
                if index < len(file_data):
                    if eocdr_offset <= index < eocdr_offset + 22:
                        if 32 <= file_data[index] <= 126:  # printable ASCII range                    
                            print(f'\033[91m{chr(file_data[index])}\033[0m', end='')
                        else:
                            print('\033[91m.\033[0m', end='')
                    elif cdfh_offsets[0] <= index < eocdr_offset:
                        if 32 <= file_data[index] <= 126:  # printable ASCII range                    
                            print(f'\033[93m{chr(file_data[index])}\033[0m', end='')
                        else:
                            print('\033[93m.\033[0m', end='')
                    elif lfh_offsets[0] <= index < cdfh_offsets[0]:
                        if 32 <= file_data[index] <= 126:  # printable ASCII range                    
                            print(f'\033[92m{chr(file_data[index])}\033[0m', end='')
                        else:
                            print('\033[92m.\033[0m', end='')
                    else:
                        pass
                else: # 값이 없으면 3칸의 공백 출력
                    print('   ',end='')
            print() # 한 line을 끝냄        
        else:       # zip 파일이 부서진 경우 - 색상 없이 hexdump 출력
            for i in range(0, 16):
                index = (line * 16) + i
                if index < len(file_data):
                    val = file_data[index]
                    print('%02x ' % val, end='')
                else:
                    print('   ', end='')
            print()
    print()

def analysis_lfh():
    global lfh_fields, all_lfh_fields, file_data
    file_file_data = ''
    file_size = ''
    print('\033[92m[*] Checking Local File Header:\033[0m')
    for lfh_file_data in lfh_datas:
        index = lfh_datas.index(lfh_file_data)
        lfh_fields = [
            {"name": "LFH Sig", "size": 4, "value": lfh_file_data[0:4]},               # Local file header signature = 0x04034b50 (PK♥♦ or "PK\3\4")
            {"name": "Ver needed", "size": 2, "value": lfh_file_data[4:6]},            # Version needed to extract (minimum)
            {"name": "GPB flag", "size": 2, "value": lfh_file_data[6:8]},              # General purpose bit flag
            {"name": "Comp method", "size": 2, "value": lfh_file_data[8:10]},          # Compression method; e.g. none = 0, DEFLATE = 8 (or "\0x08\0x00")
            {"name": "Mod time", "size": 2, "value": lfh_file_data[10:12]},            # File last modification time
            {"name": "Mod date", "size": 2, "value": lfh_file_data[12:14]},            # File last modification date
            {"name": "CRC-32", "size": 4, "value": lfh_file_data[14:18]},              # CRC-32 of uncompressed file_data
            {"name": "Comp size", "size": 4, "value": lfh_file_data[18:22]},           # Compressed size (or 0xffffffff for ZIP64)
            {"name": "Uncomp size", "size": 4, "value": lfh_file_data[22:26]},         # Uncompressed size (or 0xffffffff for ZIP64)
            {"name": "File name len", "size": 2, "value": lfh_file_data[26:28]},       # File name length (n)
            {"name": "Extra field len", "size": 2, "value": lfh_file_data[28:30]},     # Extra field length (m)
        ]

        file_name_len = int.from_bytes(lfh_fields[9]["value"], "little")
        extra_field_len = int.from_bytes(lfh_fields[10]["value"], "little")

        lfh_fields.append({                                                        # File name(30~)
            "name": "File name",
            "size": file_name_len,
            "value": lfh_file_data[30:30 + file_name_len]
        })

        lfh_fields.append({                                                        # Extra field(30+n~)
            "name": "Extra field",
            "size": extra_field_len,
            "value": lfh_file_data[30 + file_name_len:30 + file_name_len + extra_field_len]
        })

        # Extract and store file data
        file_data_offset = 30 + file_name_len + extra_field_len
        file_data_length = int.from_bytes(lfh_fields[7]["value"], "little")
        file_data_value = lfh_file_data[file_data_offset:file_data_offset + file_data_length]

        lfh_fields.append({
            "name": "File data",
            "size": file_data_length,
            "value": file_data_value
        })

        # GPB Flags의 값이 0x08일 때 Data descriptor가 생성됨
        # 4bytes: CRC-32, 4bytes: Compressed size, 4bytes: Uncompressed size
        gpb_flag_value = int.from_bytes(lfh_fields[2]["value"], "little")
        if gpb_flag_value & 0x08:
            data_descriptor_offset = 30 + file_name_len + extra_field_len
            data_descriptor = lfh_file_data[data_descriptor_offset:data_descriptor_offset + 12]
            lfh_fields.append({
            "name": "data descriptor",
            "size": 12,
            "value": data_descriptor
            })

        all_lfh_fields.append(lfh_fields)

        # Hex Dump of file file_data
        print(f'\033[92m* Hex Dump of LFH {index + 1}:\033[0m')
        for i in range(0, len(lfh_file_data), 16):
            hex_values = ' '.join(f'{byte:02X}' for byte in lfh_file_data[i:i+16])
            ascii_values = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in lfh_file_data[i:i+16])
            print(f'\033[96m{i:08X}\033[0m: {hex_values:<48} {ascii_values}')

        # LFH의 내용을 표로 출력
        print(f'\033[92m* Analysis of LFH {index + 1}:\033[0m')
        print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')
        print('| Field Name                | Size(Bytes) | Field Value (Hex)                      | Field Value (Dec/Str)                  |')
        print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')
        for field in lfh_fields:
            flag_descriptions=''
            little_endian_value = field['value'][::-1] # 리틀 엔디안 형식으로 바이트 배열을 뒤집기
            hex_values = '0x' + ''.join(f'{byte:02x}' for byte in little_endian_value) # 각 value를 16진수 형식으로 변환
            if field["size"] != 0:
                if field['name'] == "Comp method":
                    comp_method = int.from_bytes(field['value'], 'little')
                    comp_method_meaning = compression_methods.get(comp_method, "unknown")
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {comp_method}: {comp_method_meaning:<35} |')
                elif field['name'] == "GPB flag":
                    gpb_flag = int.from_bytes(field['value'], 'little')
                    for bit in range(16):
                        if gpb_flag & (1 << bit):
                            # 비트에 해당하는 값이 있으면 해당 디스크립션을 출력
                            flag_description = gpb_flags.get(bit, None)
                            if flag_description:
                                flag_descriptions += flag_description + '  '
                    if not flag_descriptions:
                        flag_descriptions = "no flags"
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {flag_descriptions:<38} |')
                elif field['name'] == "Mod time":
                    hours, minutes, seconds = calc_time(field['value'])
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {hours}:{minutes}:{seconds:<32} |')
                elif field['name'] == "Mod date":
                    year, month, day = calc_date(field['value'])
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {year}-{month}-{day:<30} |')
                elif field['name'] in ("LFH Sig", "File name"):
                    ascii_value = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in field['value'])  # 바이트를 출력 가능한 문자로 변환
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {ascii_value:<38} |')
                elif field['name'] == "Extra field":
                    file_file_data = hex_values
                    file_size = field['size']
                    print(f'| {field["name"]:<25} | {file_size:<11} | {file_file_data:<79} |')
                elif field['name'] == "data descriptor":
                    # crc32 = int.from_bytes(field['value'][0:4], 'little')
                    # comp_size = int.from_bytes(field['value'][4:8], 'little')
                    # uncomp_size = int.from_bytes(field['value'][8:12], 'little')
                    # print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | crc:{crc32}, comp_size:{comp_size}, uncomp_size: {uncomp_size} |')
                    pass
                else:   # 그 외 값들은 일반적으로 출력
                    dec_value = int.from_bytes(field['value'], 'little') # 10진수로 변환
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {dec_value:<38} |')
            else:
                print(f'| {field["name"]:<25} | 0{" " * 9}  | -{" " * 37} | -{" " * 37} |')

        print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')

        # print(f'\033[92m* Analysis of file {index + 1}:\033[0m')
        # print(' - file file_data: ', file_file_data)
        # print(' - file name: ', lfh_fields[11]["value"].decode('utf-8'))
        # print(' - file size: ', file_size, 'bytes')
        # print(' - file signature: ')
        # print()
        
    print()

def analysis_cdfh():
    global cdfh_fields, all_cdfh_fields
    file_file_data = ''
    file_size = ''
    print('\033[93m[*] Checking Central Directory File Header:\033[0m')
    for cdfh_file_data in cdfh_datas:
        index = cdfh_datas.index(cdfh_file_data)
        cdfh_fields = [
            {"name": "CDFH Sig", "size": 4, "value": cdfh_file_data[0:4]},               # Central directory file header signature = 0x02014b50
            {"name": "Ver made by", "size": 2, "value": cdfh_file_data[4:6]},            # Version made by
            {"name": "Ver needed", "size": 2, "value": cdfh_file_data[6:8]},             # Version needed to extract (minimum)
            {"name": "GPB flag", "size": 2, "value": cdfh_file_data[8:10]},              # General purpose bit flag
            {"name": "Comp method", "size": 2, "value": cdfh_file_data[10:12]},          # Compression method
            {"name": "Mod time", "size": 2, "value": cdfh_file_data[12:14]},             # File last modification time
            {"name": "Mod date", "size": 2, "value": cdfh_file_data[14:16]},             # File last modification date
            {"name": "CRC-32", "size": 4, "value": cdfh_file_data[16:20]},               # CRC-32 of uncompressed file_data
            {"name": "Comp size", "size": 4, "value": cdfh_file_data[20:24]},            # Compressed size (or 0xffffffff for ZIP64)
            {"name": "Uncomp size", "size": 4, "value": cdfh_file_data[24:28]},          # Uncompressed size (or 0xffffffff for ZIP4)
            {"name": "File name len", "size": 2, "value": cdfh_file_data[28:30]},        # File name length (n)
            {"name": "Extra field len", "size": 2, "value": cdfh_file_data[30:32]},      # Extra field length (m)
            {"name": "File comment len", "size": 2, "value": cdfh_file_data[32:34]},     # File comment length (k)
            {"name": "Disk num start", "size": 2, "value": cdfh_file_data[34:36]},       # Disk number where file starts (or 0xffff for ZIP64)
            {"name": "Int file attr", "size": 2, "value": cdfh_file_data[36:38]},        # Internal file attributes
            {"name": "Ext file attr", "size": 4, "value": cdfh_file_data[38:42]},        # External file attributes
            {"name": "Rel offset LH", "size": 4, "value": cdfh_file_data[42:46]},        # Relative offset of local file header (or 0xffffffff for ZIP64). 
        ]

        file_name_len = int.from_bytes(cdfh_fields[10]["value"], "little")
        extra_field_len = int.from_bytes(cdfh_fields[11]["value"], "little")
        file_comment_len = int.from_bytes(cdfh_fields[12]["value"], "little")

        cdfh_fields.append({                                                        # File name(46)
            "name": "File name",
            "size": file_name_len,
            "value": cdfh_file_data[46:46 + file_name_len]
        })

        cdfh_fields.append({                                                        # Extra field(46+n)
            "name": "Extra field",
            "size": extra_field_len,
            "value": cdfh_file_data[46 + file_name_len:46 + file_name_len + extra_field_len]
        })

        cdfh_fields.append({                                                        # file Comment(46+n+m)
            "name": "File comment",
            "size": file_comment_len,
            "value": cdfh_file_data[46 + file_name_len + extra_field_len:46 + file_name_len + extra_field_len + file_comment_len]
        })

        all_cdfh_fields.append(cdfh_fields)

        # Hex Dump of file file_data
        print(f'\033[93m* Hex Dump of CDFH {index + 1}:\033[0m')
        for i in range(0, len(cdfh_file_data), 16):
            hex_values = ' '.join(f'{byte:02X}' for byte in cdfh_file_data[i:i+16])
            ascii_values = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in cdfh_file_data[i:i+16])
            print(f'\033[96m{i:08X}\033[0m: {hex_values:<48} {ascii_values}')

        # CDFH의 내용을 표로 출력
        print(f'\033[93m* Analysis of CDFH {index + 1}:\033[0m')
        print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')
        print('| Field Name                | Size(Bytes) | Field Value (Hex)                      | Field Value (Dec/Str)                  |')
        print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')

        for field in cdfh_fields:
            little_endian_value = field['value'][::-1] # 리틀 엔디안 형식으로 바이트 배열을 뒤집기
            hex_values = '0x' + ''.join(f'{byte:02x}' for byte in little_endian_value) # 각 value를 16진수 형식으로 변환
            flag_descriptions=''
            if field["size"] != 0:
                if field['name'] == "Comp method":
                    comp_method = int.from_bytes(field['value'], 'little')
                    comp_method_meaning = compression_methods.get(comp_method, "unknown")
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {comp_method}: {comp_method_meaning:<35} |')
                elif field['name'] in ("Ver needed", "Ver made by"):
                    ver = int.from_bytes(field['value'], 'little')
                    ver_lower = ver >> 8
                    ver_upper = ver & 0xFF
                    ver_meaning = version_required.get(ver_upper, "unknown")
                    # 하위 값이 있어 버전이 표시된다면, 버전을 출력
                    if ver_lower != 0:
                        ver_lower_decimal = ver_lower / 10
                        ver_meaning += f" (ver: {ver_lower_decimal:.1f})"
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {ver_meaning:<38} |')
                elif field['name'] == "GPB flag":
                    # 각 비트당 설정되어 있는 값을 gpb_flags에서 가져와 출력
                    gpb_flag = int.from_bytes(field['value'], 'little')
                    for bit in range(16):
                        if gpb_flag & (1 << bit):
                            # 비트에 해당하는 값이 있으면 해당 디스크립션을 출력
                            flag_description = gpb_flags.get(bit, None)
                            if flag_description:
                                flag_descriptions += flag_description + '  '
                    if not flag_descriptions:
                        flag_descriptions = "no flags"
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {flag_descriptions:<38} |')
                elif field['name'] == "Mod time":
                    hours, minutes, seconds = calc_time(field['value'])
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {hours}:{minutes}:{seconds:<32} |')
                elif field['name'] == "Mod date":
                    year, month, day = calc_date(field['value'])
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {year}-{month}-{day:<30} |')
                elif field['name'] == "Int file attr":
                    int_file_attr = int.from_bytes(field['value'], 'little')
                    int_file_attr_meaning = internal_file_attributes.get(int_file_attr, "unknown")
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {int_file_attr_meaning:<38} |')
                elif field['name'] == "Extra field":
                    file_file_data = hex_values
                    file_size = field['size']
                    print(f'| {field["name"]:<25} | {file_size:<11} | {file_file_data:<79} |')
                elif field['name'] in ("CDFH Sig", "File name", "File comment"):
                    ascii_value = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in field['value'])  # 바이트를 출력 가능한 문자로 변환
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {ascii_value:<38} |')
                else:
                    dec_value = int.from_bytes(field['value'], 'little') # 10진수로 변환
                    print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {dec_value:<38} |')
            else:
                print(f'| {field["name"]:<25} | 0{" " * 9}  | -{" " * 37} | -{" " * 37} |')
        print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')
    print()

def analysis_eocdr():
    global eocdr_fields
    print('\033[91m[*] Checking End of Central Directory Record:\033[0m')

    eocdr_fields = [
        {"name": "EOCDR Sig", "size": 4, "value": eocdr_data[0:4]},           # End of central directory signature = 0x06054b50
        {"name": "Disk num", "size": 2, "value": eocdr_data[4:6]},            # Number of this disk (or 0xffff for ZIP64)
        {"name": "CD start disk", "size": 2, "value": eocdr_data[6:8]},       # Disk where central directory starts (or 0xffff for ZIP64)
        {"name": "CD rec on disk", "size": 2, "value": eocdr_data[8:10]},     # Number of central directory records on this disk (or 0xffff for ZIP64)
        {"name": "Total CD rec", "size": 2, "value": eocdr_data[10:12]},      # Total number of central directory records (or 0xffff for ZIP64)
        {"name": "CD size (bytes)", "size": 4, "value": eocdr_data[12:16]},   # Size of central directory (bytes) (or 0xffffffff for ZIP64)
        {"name": "CD offset", "size": 4, "value": eocdr_data[16:20]},         # Offset of start of central directory, relative to start of archive (or 0xffffffff for ZIP64)
        {"name": "Comment len", "size": 2, "value": eocdr_data[20:22]},       # Comment length (n)
    ]

    # Comment 필드 추가
    comment_length = int.from_bytes(eocdr_fields[-1]["value"],"little") # 마지막 필드에서 코멘트 길이 가져오기
    eocdr_fields.append({
        "name": "Comment",
        "size": comment_length,
        "value": eocdr_data[22:22 + comment_length]
    })

    # Hex Dump of file file_data
    print(f'\033[91m* Hex Dump of EOCDR:\033[0m')
    for i in range(0, len(eocdr_data), 16):
            hex_values = ' '.join(f'{byte:02X}' for byte in eocdr_data[i:i+16])
            ascii_values = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in eocdr_data[i:i+16])
            print(f'\033[96m{i:08X}\033[0m: {hex_values:<48} {ascii_values}')

    # EOCDR의 내용을 표로 출력
    print(f'\033[91m* Analysis of EOCDR:\033[0m')
    print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')
    print('| Field Name                | Size(Bytes) | Field Value (Hex)                      | Field Value (Dec/Str)                  |')
    print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')
    
    for field in eocdr_fields:
        # 리틀 엔디안 형식으로 바이트 배열을 뒤집기
        little_endian_value = field['value'][::-1]

        # 각 value를 16진수 형식으로 변환
        hex_values = '0x' + ''.join(f'{byte:02x}' for byte in little_endian_value)
        # 10진수로 변환

        # 문자열로 변환 (ASCII로 변환 가능)

        if field["size"] != 0:
            if field['name'] in ('EOCDR Sig', 'Comment'):
                ascii_value = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in field['value'])  # 바이트를 출력 가능한 문자로 변환
                print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {ascii_value:<38} |')
            else:
                dec_value = int.from_bytes(field['value'], 'little')
                print(f'| {field["name"]:<25} | {field["size"]:<11} | {hex_values:<38} | {dec_value:<38} |')
        else:
            print(f'| {field["name"]:<25} | 0{" " * 9}  | -{" " * 37} | -{" " * 37} |')
    print('+---------------------------+-------------+----------------------------------------+----------------------------------------+')
    print()

def calculate_crc(data):
    return binascii.crc32(data) & 0xffffffff

def check_crc_corruption():
    suspicious_files = []

    # Check LFH and CDFH fields
    for lfh, cdfh in zip(all_lfh_fields, all_cdfh_fields):
        file_name = next(field['value'].decode('utf-8') for field in lfh if field['name'] == 'File name')
        lfh_crc32_value = next(int.from_bytes(field['value'], 'little') for field in lfh if field['name'] == 'CRC-32')
        cdfh_crc32_value = next(int.from_bytes(field['value'], 'little') for field in cdfh if field['name'] == 'CRC-32')

        # Extract file data based on LFH information
        file_data = next(field['value'] for field in lfh if field['name'] == 'File data')

        # Calculate CRC-32
        calculated_crc = calculate_crc(file_data)
        print("[*] Checking CRC for file:", file_name)
        print(f"- Calculated CRC: {calculated_crc}, LFH CRC: {lfh_crc32_value}, CDFH CRC: {cdfh_crc32_value}")

        if calculated_crc != lfh_crc32_value or calculated_crc != cdfh_crc32_value:
            print(f"\033[91m[-] Corruption Detected! CRC mismatch in file: {file_name}\033[0m")
            suspicious_files.append(file_name)

    if not suspicious_files:
        print("\033[94m[+] No corruption detected.\033[0m")
    print()

def identify_extension(file_data):
    for signature, extension in file_signatures.signature_to_extension.items():
        if file_data.startswith(signature):
            return extension
    return 'unknown'

def list_files(zip_ref):
    print("[*] Listing files in the ZIP archive:")
    for file_info in zip_ref.infolist():
        file_name = file_info.filename
        file_size = file_info.file_size
        compress_size = file_info.compress_size
        file_ext = os.path.splitext(file_name)[1][1:]  # 파일 확장자 추출 ('.' 제거)

        # 파일 내용을 읽어 시그니처 기반 확장자 식별
        with zip_ref.open(file_info) as file:
            file_data = file.read(64)  # 처음 64바이트만 읽기
            identified_ext = identify_extension(file_data)

        print(f"- File: {file_name}, Size: {file_size}, Compressed: {compress_size}, Extension: {file_ext}, Identified Extension: {identified_ext}")

        # 파일 내용 출력
        ascii_values = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in file_data)
        print(f"- ASCII Dump: {ascii_values}")

        if identified_ext == 'unknown':
            print(f'\033[93m[?] Unknown file extension({file_ext}) detected. Investigate the signiture manually.\033[0m')
        elif file_ext != identified_ext:  # 시그니처 - 확장자 불일치 감지 
            print('\033[91m[-] File tampering detected!\033[0m')  # 빨간색 문구로 출력
        else:
            print('\033[94m[+] File extension is consistent with the signature.\033[0m')
    print()

def detect_size_mismatch(zip_ref):
    suspicious_files = []

    for file_info in zip_ref.infolist():
        file_name = file_info.filename
        declared_comp_size = file_info.compress_size
        declared_uncomp_size = file_info.file_size

        # Extract file data
        with zip_ref.open(file_info) as file:
            file_data = file.read()

        actual_comp_size = len(file_data)
        actual_uncomp_size = len(file_data)  # Assuming no compression for simplicity

        print(f"[*] Checking sizes for file: {file_name}")
        print(f"- Declared Comp Size: {declared_comp_size}, Actual Comp Size: {actual_comp_size}")
        print(f"- Declared Uncomp Size: {declared_uncomp_size}, Actual Uncomp Size: {actual_uncomp_size}")

        if actual_comp_size != declared_comp_size or actual_uncomp_size != declared_uncomp_size:
            print(f"\033[91m[-] Size Mismatch Detected! Size mismatch in file: {file_name}\033[0m")
            suspicious_files.append(file_name)

    if not suspicious_files:
        print("\033[94m[+] No size mismatch detected.\033[0m")
    print()

if __name__ == '__main__':    
    # 안전한 실행을 위하여, 파이썬 실행 파일과 같은 위치에 있는 파일만 실행하도록 한다.
    filename = input("[*] Enter the name of the ZIP file (without extension): ")
        
    # 외부 입력 검증
    if not filename.isalnum():
        print("[*] Error: The filename should only contain alphanumeric characters.")
        print("[-] Program will be terminated.")
        exit(1)

    # 입력 길이 제한
    if len(filename) == 0:
        print("[*] Error: The filename cannot be empty.")
        print("[-] Program will be terminated.")
        exit(1)

    if len(filename) > 255:
        print("[*] Error: The filename is too long.")
        print("[-] Program will be terminated.")
        exit(1)

    # 파일 경로 조작 방지
    safe_filename = os.path.join(os.getcwd(), filename + '.zip')

    try:
        with open(safe_filename, 'rb') as f:
            file_data += f.read()
            #print("[*] File read successfully.")

    except FileNotFoundError:
        print(f"[-] Error: The file '{filename}.zip' does not exist in this folder.")
        print(f"[-] Program will be terminated.")
        exit(1)
    except PermissionError:
        print(f"[-] Error: Permission denied while trying to read the file '{filename}.zip'.")
        print(f"[-] Program will be terminated.")
        exit(1)
    except IsADirectoryError:
        print(f"[-] Error: '{filename}.zip' is a directory, not a file.")
        print(f"[-] Program will be terminated.")
        exit(1)
    except Exception as e:
        print(f"[-] Error: An unexpected error occurred while reading the file: {e}")
        print(f"[-] Program will be terminated.")
        exit(1)

    # 기본 파일 분석 함수 호출
    find_parts()
    hexdump()
    analysis_lfh()
    analysis_cdfh()
    analysis_eocdr()

    # 다른 검사 이전에 CRC 체크 먼저 수행(zipfile 모듈은 CRC 손상 시 에러 발생)
    check_crc_corruption()
    
    # 포렌식적 분석 함수 호출
    try:
        with zipfile.ZipFile(safe_filename, 'r') as zip_ref:
            list_files(zip_ref)
            detect_size_mismatch(zip_ref)
    except RuntimeError as e:
        print(f"[-] Error: Error occurred while listing files or extracting files: {e}")
        print(f"[-] Program will be terminated.")
        exit(1)
    except zipfile.BadZipFile as e:
        print(f"[-] Error: Bad ZIP file: {e}")
        print(f"[-] Program will be terminated.")
        exit(1)
    except zipfile.LargeZipFile:
        print("[-] Error: ZIP file requires ZIP64 functionality but it is not enabled.")
        print(f"[-] Program will be terminated.")
        exit(1)
    except Exception as e:
        print(f"[-] Error: An unexpected error occurred: {e}")
        print(f"[-] Program will be terminated.")
        exit(1)

    print("[+] Program has finished successfully.")
    