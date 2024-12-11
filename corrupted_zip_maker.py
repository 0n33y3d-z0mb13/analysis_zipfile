import zipfile
import os

def create_corrupted_zip(zip_filename):
    """Create a ZIP file with corrupted signatures."""
    # 파일 내용
    file_content = b"Hello, world! This is a test file."

    # ZIP 파일 생성
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        zipf.writestr('normal_file.txt', file_content)

    # ZIP 파일 열기
    with open(zip_filename, 'r+b') as f:
        zip_data = f.read()

        # EOCDR 시그니처 망가뜨리기
        eocdr_signature = b'\x50\x4b\x05\x06'
        corrupted_eocdr_signature = b'\x51\x4c\x06\x07'
        zip_data = zip_data.replace(eocdr_signature, corrupted_eocdr_signature)

        # CDFH 시그니처 망가뜨리기
        cdfh_signature = b'\x50\x4b\x01\x02'
        corrupted_cdfh_signature = b'\x51\x4c\x02\x03'
        zip_data = zip_data.replace(cdfh_signature, corrupted_cdfh_signature)

        # LFH 시그니처 망가뜨리기
        lfh_signature = b'\x50\x4b\x03\x04'
        corrupted_lfh_signature = b'\x51\x4c\x04\x05'
        zip_data = zip_data.replace(lfh_signature, corrupted_lfh_signature)

        # 변경된 데이터 저장
        f.seek(0)
        f.write(zip_data)

    print(f"Corrupted ZIP file '{zip_filename}' created with corrupted signatures.")

def main():
    zip_filename = 'corrupted.zip'
    create_corrupted_zip(zip_filename)

if __name__ == "__main__":
    main()