import zipfile
import binascii
import os

def create_corrupted_zip(zip_filename, txt_filename, txt_content):
    # ZIP 파일 생성
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        # 텍스트 파일 추가
        zipf.writestr(txt_filename, txt_content)

    # ZIP 파일 열기
    with zipfile.ZipFile(zip_filename, 'r') as zipf:
        # 텍스트 파일의 CRC 값을 조작
        for file_info in zipf.infolist():
            if file_info.filename == txt_filename:
                # 원래 CRC 값 출력
                original_crc = file_info.CRC
                print(f"Original CRC: {original_crc:#010x}")

                # 조작된 CRC 값 설정 (임의의 값으로 변경)
                corrupted_crc = original_crc ^ 0xFFFFFFFF  # 원래 CRC 값을 반전시킴
                print(f"Corrupted CRC: {corrupted_crc:#010x}")

                # ZIP 파일의 바이너리 데이터를 읽어와서 수정
                with open(zip_filename, 'rb') as f:
                    zip_data = f.read()

                # CRC 값의 위치 찾기
                crc_offset = zip_data.find(file_info.filename.encode()) + len(file_info.filename) + 14
                print(f"CRC Offset: {crc_offset}")

                # CRC 값을 조작된 값으로 변경
                corrupted_zip_data = (
                    zip_data[:crc_offset] +
                    corrupted_crc.to_bytes(4, byteorder='little') +
                    zip_data[crc_offset + 4:]
                )

                # 조작된 ZIP 파일 저장
                with open(zip_filename, 'wb') as f:
                    f.write(corrupted_zip_data)

                print(f"Corrupted ZIP file '{zip_filename}' created with manipulated CRC for '{txt_filename}'.")

if __name__ == "__main__":
    zip_filename = 'crc.zip'
    txt_filename = 'helloworld.txt'
    txt_content = 'Hello, world! This is a test file.'

    create_corrupted_zip(zip_filename, txt_filename, txt_content)