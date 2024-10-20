import zipfile

# 파라미터: data - 분석할 데이터를 입력, 리턴값: 없음
# 함수설명: 입력된 데이터를 16개씩 끊어 2자리 16진수로 표시 및 해당 16진수의 문자로 표시(출력 불가능할 경우 .으로 표시)
def hexdump(data):
    print('HexDump:')

    # 헤더 출력
    print('\033[96mOffsef(h) 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f', end='')  # print the header
    print('  ', end='')
    print('Decoded text\033[0m')

    # End of Central Directory Record (EOCDR)를 찾아 색상으로 표시하기 위한 시그니처와 주소
    eocdr_signature = b'\x50\x4b\x05\x06'
    eocdr_offset = data.rfind(eocdr_signature)

    # Central Directory Header (CDH)를 찾아 색상으로 표시하기 위한 시그니처와 주소
    cdh_signature = b'\x50\x4b\x01\x02'
    cdh_offsets = []        # CHD는 여러개일 수 있으므로 리스트로 저장
    offset = data.find(cdh_signature) 
    while offset != -1:
        cdh_offsets.append(offset)
        offset = data.find(cdh_signature, offset + 1)

    # Local File Header (LFH)를 찾아 색상으로 표시하기 위한 시그니처와 주소
    lfh_signature = b'\x50\x4b\x03\x04'
    lfh_offsets = []        # LFH는 여러개일 수 있으므로 리스트로 저장
    offset = data.find(lfh_signature)
    while offset != -1:
        lfh_offsets.append(offset)
        offset = data.find(lfh_signature, offset + 1)

    # 16바이트마다 한 줄씩 출력
    for line in range(0, len(data)//16+1):
        # 주소 출력
        print('\033[96m%08x: ' % (line*16), end='\033[0m')

        # 실제 값들을 출력하는 부분
        for i in range(0, 16):
            index = (line * 16) + i
            if index < len(data):
                # EOCDR 부분을 빨간색으로 표시
                if eocdr_offset <= index < eocdr_offset + 22:
                    eocdr_values = data[eocdr_offset:]  # 분석을 위해 값을 저장
                    print('\033[91m%02x \033[0m' % data[index], end='')
                elif cdh_offsets[0] <= index < eocdr_offset:
                    # CDH 부분을 노란색으로 표시
                    print('\033[93m%02x \033[0m' % data[index], end='')
                elif lfh_offsets[0] <= index < cdh_offsets[0]:
                    # LFH 부분을 초록색으로 표시
                    print('\033[92m%02x \033[0m' % data[index], end='')
                else:
                    # 나머지 값들은 흰색으로 표시
                    val = data[index]
                    print('%02x ' % val, end='')
            else: # 값이 없으면 3칸의 공백 출력
                print('   ', end='')
                
        # ASCII 값을 출력하는 부분
        print(' ', end='')  # space between hex and ASCII
        for i in range(0, 16):
            if (line*16)+i < len(data):
                char = data[(line*16)+i]
                if 32 <= char <= 126:  # printable ASCII range
                    print(chr(char), end='')
                else:
                    print('.', end='')
        print() # 한 line을 끝냄

    print()

    # LFH 값 출력
    print('\033[92m[LFH values]\033[0m')
    for offset in lfh_offsets:
        lfh_values = data[offset:offset+30]  # LFH는 최소 30바이트
        print(f'Offset: {offset}')
        print(f'Signature: {lfh_values[:4].hex()}')
        print(f'Version needed to extract: {int.from_bytes(lfh_values[4:6], "little")}')
        print(f'General purpose bit flag: {int.from_bytes(lfh_values[6:8], "little")}')
        print(f'Compression method: {int.from_bytes(lfh_values[8:10], "little")}')
        print(f'File last modification time: {int.from_bytes(lfh_values[10:12], "little")}')
        print(f'File last modification date: {int.from_bytes(lfh_values[12:14], "little")}')
        print(f'CRC-32: {lfh_values[14:18].hex()}')
        print(f'Compressed size: {int.from_bytes(lfh_values[18:22], "little")}')
        print(f'Uncompressed size: {int.from_bytes(lfh_values[22:26], "little")}')
        print(f'File name length: {int.from_bytes(lfh_values[26:28], "little")}')
        print(f'Extra field length: {int.from_bytes(lfh_values[28:30], "little")}')
        print()

    # CDH 값 출력
    print('\033[93m[CDH values]\033[0m')
    for offset in cdh_offsets:
        cdh_values = data[offset:offset+46]  # CDH는 최소 46바이트
        print(f'Offset: {offset}')
        print(f'Signature: {cdh_values[:4].hex()}')
        print(f'Version made by: {int.from_bytes(cdh_values[4:6], "little")}')
        print(f'Version needed to extract: {int.from_bytes(cdh_values[6:8], "little")}')
        print(f'General purpose bit flag: {int.from_bytes(cdh_values[8:10], "little")}')
        print(f'Compression method: {int.from_bytes(cdh_values[10:12], "little")}')
        print(f'File last modification time: {int.from_bytes(cdh_values[12:14], "little")}')
        print(f'File last modification date: {int.from_bytes(cdh_values[14:16], "little")}')
        print(f'CRC-32: {cdh_values[16:20].hex()}')
        print(f'Compressed size: {int.from_bytes(cdh_values[20:24], "little")}')
        print(f'Uncompressed size: {int.from_bytes(cdh_values[24:28], "little")}')
        print(f'File name length: {int.from_bytes(cdh_values[28:30], "little")}')
        print(f'Extra field length: {int.from_bytes(cdh_values[30:32], "little")}')
        print(f'File comment length: {int.from_bytes(cdh_values[32:34], "little")}')
        print(f'Disk number start: {int.from_bytes(cdh_values[34:36], "little")}')
        print(f'Internal file attributes: {int.from_bytes(cdh_values[36:38], "little")}')
        print(f'External file attributes: {int.from_bytes(cdh_values[38:42], "little")}')
        print(f'Relative offset of local header: {int.from_bytes(cdh_values[42:46], "little")}')
        print()

    # EOCDR 값 출력
    print('\033[91m[EOCDR values]\033[0m')
    print(f'Signature: {eocdr_values[:4].hex()}')
    print(f'Number of this disk: {int.from_bytes(eocdr_values[4:6], "little")}')
    print(f'Number of the disk with the start of the central directory: {int.from_bytes(eocdr_values[6:8], "little")}')
    print(f'Total number of entries in the central directory on this disk: {int.from_bytes(eocdr_values[8:10], "little")}')
    print(f'Total number of entries in the central directory: {int.from_bytes(eocdr_values[10:12], "little")}')
    print(f'Size of the central directory: {int.from_bytes(eocdr_values[12:16], "little")}')
    print(f'Offset of start of central directory with respect to the starting disk number: {int.from_bytes(eocdr_values[16:20], "little")}')
    print(f'ZIP file comment length: {int.from_bytes(eocdr_values[20:22], "little")}')


if __name__ == '__main__':
    data = b''
    with open('testfile.zip', 'rb') as f:
        data += f.read()

    hexdump(data)
