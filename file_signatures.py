signature_to_extension = {
    b'\x50\x4B\x03\x04': 'zip',  # ZIP 파일
    b'\x50\x4B\x05\x06': 'zip',  # ZIP 파일 (empty archive)
    b'\x50\x4B\x07\x08': 'zip',  # ZIP 파일 (spanned archive)
    b'\x25\x50\x44\x46': 'pdf',  # PDF 파일
    b'\xFF\xD8\xFF': 'jpg',      # JPEG 파일
    b'\x89\x50\x4E\x47': 'png',  # PNG 파일
    b'\x47\x49\x46\x38': 'gif',  # GIF 파일
    b'\x42\x4D': 'bmp',          # BMP 파일
    b'\x49\x49\x2A\x00': 'tif',  # TIFF 파일 (little-endian)
    b'\x4D\x4D\x00\x2A': 'tif',  # TIFF 파일 (big-endian)
    b'\x7F\x45\x4C\x46': 'elf',  # ELF 파일 (Linux 실행 파일)
    b'\xCA\xFE\xBA\xBE': 'class', # Java 클래스 파일
    b'\x25\x21': 'ps',           # PostScript 파일
    b'\x52\x49\x46\x46': 'avi',  # AVI 파일
    b'\x4F\x67\x67\x53': 'ogg',  # OGG 파일
    b'\x1F\x8B': 'gz',           # GZIP 파일
    b'\x42\x5A\x68': 'bz2',      # BZIP2 파일
    b'\x37\x7A\xBC\xAF\x27\x1C': '7z', # 7-Zip 파일
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'doc/xls/ppt',  # MS Office (OLE Compound Document)
    b'\x50\x4B\x03\x04': 'docx/pptx/xlsx', # Office Open XML (ZIP 기반)
    b'\x52\x61\x72\x21\x1A\x07\x00': 'rar',  # RAR 파일
    b'\x75\x73\x74\x61\x72': 'tar',         # TAR 파일
    b'\x66\x4C\x61\x43': 'flac',           # FLAC 파일
    b'\x1A\x45\xDF\xA3': 'mkv',            # Matroska 영상 파일
    b'\x00\x00\x01\xBA': 'mpg',            # MPEG 영상 파일
    b'\x00\x00\x01\xB3': 'mpg',            # MPEG 영상 파일
    b'\x66\x74\x79\x70': 'mp4',            # MP4 파일
    b'\x49\x44\x33': 'mp3',                # MP3 파일
    b'\x52\x49\x46\x46': 'wav',            # WAV 파일
    b'\x30\x26\xB2\x75\x8E\x66\xCF\x11': 'asf',  # ASF/WMV/WMA 파일
    b'\x4D\x5A': 'exe',                    # EXE 실행 파일
    b'\x25\x21': 'ps',                     # PostScript 파일
    b'\x46\x57\x53': 'swf',                # Shockwave Flash 파일
    b'\x52\x61\x72\x21': 'rar',            # RAR 파일 (버전 1.5 이상)
    b'\x0A\x05\x01\x08': 'pcap',           # PCAP 파일
    b'\x23\x21': 'sh',                     # Shell Script 파일
}
