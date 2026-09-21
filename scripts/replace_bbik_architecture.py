from pathlib import Path
from shutil import copy2
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile


SOURCE = Path('/Users/adieu/Desktop/학교/폴리텍/최종과제/과제관련/시스원_이력서_김연동_기타활동_기업프로젝트만_최종본.docx')
TARGET = SOURCE.with_name('시스원_이력서_김연동_삑아키텍처반영_최종본.docx')
ARCHITECTURE = Path('/tmp/bbik_assets/AppinToss/bbik 시스템 아키텍처.jpg')


copy2(SOURCE, TARGET)
with NamedTemporaryFile(suffix='.docx', delete=False) as temporary:
    temporary_path = Path(temporary.name)

with ZipFile(TARGET, 'r') as source_zip, ZipFile(temporary_path, 'w', ZIP_DEFLATED) as target_zip:
    for item in source_zip.infolist():
        data = ARCHITECTURE.read_bytes() if item.filename == 'word/media/image5.jpg' else source_zip.read(item.filename)
        target_zip.writestr(item, data)

temporary_path.replace(TARGET)
print(TARGET)