from pathlib import Path
from shutil import copy2

from docx import Document


SOURCE = Path('/Users/adieu/Desktop/학교/폴리텍/최종과제/과제관련/시스원_이력서_김연동_기타활동추가_복구본.docx')
TARGET = SOURCE.with_name('시스원_이력서_김연동_기타활동확장_최종본.docx')


copy2(SOURCE, TARGET)
document = Document(TARGET)
activity_table = document.tables[5]

activities = [
    [
        '2026.05',
        'AWS 프리 티어와 비용 모니터링 조사 발표',
        '한국폴리텍대학 광명융합기술교육원',
        'AWS Budgets·Cost Explorer·CloudWatch 결제 알람 및 글로벌 리전 비용 관리 조사',
    ],
    [
        '2026.05.28',
        'NginX를 살려라 CTF / NGINX 방어 프로젝트',
        '한국폴리텍대학 광명융합기술교육원',
        'NLB + EC2 3대 구성, 다중 자동복구·SSH 방어·Teams 실시간 알람 검증',
    ],
    [
        '2026.05.08',
        'AI EXPO KOREA 2026 관람 및 기술 리서치',
        '한국인공지능협회·서울메쎄·인공지능신문',
        'AI 에이전트·LLM·RAG·GPU 인프라 기술을 조사하고 팀 관람 리포트 작성',
    ],
]

for values in activities:
    row = activity_table.add_row()
    for cell, value in zip(row.cells, values):
        cell.text = value

document.save(TARGET)
print(TARGET)