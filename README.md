# ZIP File Analysis

ZIP 파일의 구조를 분석하고, 파일의 무결성을 확인하며, 숨겨진 데이터를 감지하는 Python 스크립트입니다. 이 스크립트는 ZIP 파일 내의 파일 크기, CRC 값, 압축 크기 등을 비교하여 변조된 파일을 감지할 수 있습니다.

## 기능

- ZIP 파일 내의 파일 목록 출력
- 파일의 CRC 값 확인 및 변조 감지
- 파일 크기 및 압축 크기 비교
- 숨겨진 데이터 감지

## 사용법

### 요구 사항

- Python 3.x
- 필요한 라이브러리: `binascii`, `os`, `zipfile`, `tempfile`

### 실행 방법

1. 스크립트를 실행할 디렉토리에 `zipfileanalysis.py`, `file_signatures.py` 파일을 저장합니다.
2. 터미널 또는 명령 프롬프트를 열고, 스크립트가 있는 디렉토리로 이동합니다.
3. 다음 명령어를 실행하여 스크립트를 실행합니다:
4. ZIP 파일의 이름을 입력하라는 메시지가 표시되면, 분석할 ZIP 파일의 이름을 입력합니다 (확장자는 제외).

### 예시

```sh
[*] Enter the name of the ZIP file (without extension): test_hidden_data
```

## 함수 설명

### `find_parts()`

ZIP 파일의 EOCDR, CDFH, LFH 시그니처를 찾아 각 파트의 위치를 식별하고 데이터를 추출합니다.

### `hexdump()`

파일 데이터를 16진수 형식으로 출력합니다. EOCDR, CDFH, LFH 부분을 색상으로 구별하여 출력합니다.

### `analysis_lfh()`

LFH(Local File Header)를 분석하여 각 필드의 값을 출력합니다. 각 파일마다 `lfh_fields`를 생성하고, 이를 리스트에 저장하여 모든 파일에 대한 정보를 유지합니다.

### `analysis_cdfh()`

CDFH(Central Directory File Header)를 분석하여 각 필드의 값을 출력합니다. 각 파일마다 `cdfh_fields`를 생성하고, 이를 리스트에 저장하여 모든 파일에 대한 정보를 유지합니다.

### `analysis_eocdr()`

EOCDR(End of Central Directory Record)을 분석하여 각 필드의 값을 출력합니다.

### `calculate_crc(data)`

주어진 데이터의 CRC-32 값을 계산합니다.

### `check_crc_corruption()`

LFH와 CDFH 필드에 있는 CRC-32 값을 사용하여 파일의 무결성을 확인합니다. CRC 값이 일치하지 않으면 파일이 변조되었음을 감지합니다.

### `list_files(zip_ref)`

ZIP 파일 내의 파일 목록을 출력하고, 파일의 시그니처를 기반으로 확장자를 식별합니다. 시그니처와 확장자가 일치하지 않으면 파일 변조를 감지합니다.

### `detect_size_mismatch(zip_ref)`

ZIP 파일 내의 파일 크기와 압축 크기를 비교하여 변조를 감지합니다.

### `detect_hidden_data(zip_filename)`

ZIP 파일 내의 모든 파일을 추출한 후, 다시 ZIP 파일로 압축했을 때의 크기와 실제 ZIP 파일의 크기를 비교하여 숨겨진 데이터를 감지합니다.

## 테스트 ZIP 파일 생성

테스트를 하기 위한 ZIP파일이 첨부되어 있습니다. 아래 3개는 직접 제작한 파일입니다.
- `hello.zip`: hello.txt 1개가 포함된 일반적인 zip 파일
- `helloworld.zip`: hello.txt와 world.txt 2개가 포함된 일반적인 zip 파일
- `encrypted.zip`: hello.txt가 hello라는 패스워드로 암호화된 zip 파일

아래 세 파일은 테스트를 위해 ChatGPT를 이용하여 ZIP파일을 제작하는 스크립트로 만들어졌습니다.
- `crc.zip`: CRC가 변조된 zip 파일
- `hidden.zip`: 숨겨진 데이터가 있는 zip 파일
- `size.zip`: 압축된 파일 중 사이즈가 변조된 파일이 있는 zip 파일
- `corrupted.zip`: 각 파트의 시그니처가 손상된 zip 파일

각각 순서대로 아래의 스크립트를 실행하면 제작할 수 있습니다.
- `CRC_corrupted_zip_maker.py`
- `hidden_data_zip_maker.py`
- `size_mismatch_zip_maker.py`
- `corrupted_zip_maker.py`