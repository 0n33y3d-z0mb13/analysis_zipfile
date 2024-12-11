import zipfile
import os

def create_test_zip(zip_filename):
    """Create a test ZIP file with size mismatches."""
    # 파일 내용
    file_content = b"Hello, world! This is a test file."

    # ZIP 파일 생성
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        # 정상 파일 추가
        zipf.writestr('normal_file.txt', file_content)

        # 크기 변조된 파일 추가 (더 큰 파일)
        large_file_content = b"A" * 1024  # 1KB 파일
        zip_info = zipfile.ZipInfo('large_tampered_file.txt')
        zip_info.compress_type = zipfile.ZIP_DEFLATED
        zip_info.file_size = len(large_file_content)
        zip_info.compress_size = len(large_file_content) - 100  # 변조된 압축 크기
        zipf.writestr(zip_info, large_file_content)

    print(f"Test ZIP file '{zip_filename}' created with normal and tampered files.")

def main():
    zip_filename = 'size.zip'
    create_test_zip(zip_filename)

if __name__ == "__main__":
    main()