import zipfile
import os

def create_test_zip_with_hidden_data(zip_filename):
    """Create a test ZIP file with hidden data using various methods."""
    # 파일 내용
    file_content = b"Hello, world! This is a test file."

    # ZIP 파일 생성
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        # 정상 파일 추가
        zipf.writestr('normal_file.txt', file_content)

        # 숨겨진 데이터가 있는 파일 추가 (크기 변조)
        zip_info = zipfile.ZipInfo('hidden_data_file.txt')
        zip_info.compress_type = zipfile.ZIP_DEFLATED
        zip_info.file_size = len(file_content)
        zip_info.compress_size = len(file_content) - 10  # 변조된 압축 크기
        zipf.writestr(zip_info, file_content + b'\x00' * 10)  # 숨겨진 데이터 추가

    # ZIP 파일에 추가적인 숨겨진 데이터 추가 (파일 끝에 임의의 텍스트 파일 붙여넣기)
    with open(zip_filename, 'ab') as f:
        f.write(b'\nThis is hidden data at the end of the ZIP file.\n')

    print(f"Test ZIP file '{zip_filename}' created with normal and hidden data files.")

def main():
    zip_filename = 'hidden.zip'
    create_test_zip_with_hidden_data(zip_filename)

if __name__ == "__main__":
    main()