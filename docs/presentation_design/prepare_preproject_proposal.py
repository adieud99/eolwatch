"""Four slides INCLUDING the cover: a proposal to SysOne before project start."""
from pathlib import Path

# Reuse the exact template-copy and proportional-scaling functions, without
# running the previous revision's generation or writing its output.
HELPER = Path(__file__).resolve().with_name('reuse_base_template.py')
exec(HELPER.read_text().split('\nimport_slide(2, 3)')[0], globals())

SOURCE = Path(json.loads((HERE / 'base_revision/delivered_files.json').read_text())[0])
WORK = HERE / 'preproject_proposal'
WORK.mkdir(exist_ok=True)
OUT = WORK / 'EOLWatch_프로젝트제안요약서_김연동.pptx'
hashes = {str(p): sha(p) for p in (SOURCE, BASE)}
with ZipFile(SOURCE) as z:
    original = {n: z.read(n) for n in z.namelist()}
parts = dict(original)

TEXT = {
    2: {
        4: '제안 배경과 목적',
        5: '시스원의 유지관리·공개SW 기술지원 업무를 위한 제안',
        21: '제안 배경',
        14: '유지관리 담당자는 취약점의 영향 자산과 지원 종료 대상을 확인하고, 고객에게 처리 결과를 설명해야 합니다.\n자산 정보·분석 결과·조치 이력을 연결해 이 업무를 지원하는 웹 서비스 EOLWatch를 개발하고자 합니다.',
        22: '기대 효과',
        18: '영향 대상 파악',
        19: '변경 계획 지원',
        20: '인계·보고 지원',
        15: '구성요소와 자산을 연결해\n취약점 발생 시 확인할\n고객사·서버를 찾도록 지원',
        16: '지원 종료일·계약을 바탕으로\n업그레이드·교체 대상과\n작업 시점 검토를 지원',
        17: '담당자·조치 이력을 모아\n담당자 간 인계를 돕고\n고객 보고 근거를 확보',
    },
    3: {
        4: '주요 개발 기능',
        5: '대상 파악부터 조치·고객 보고까지 연결하는 기능 개발',
        22: '자산·구성 파악',
        24: '취약점·EOL 확인',
        23: '조치 업무 관리',
        25: '재점검·보고',
        18: '서버·프로젝트 분석으로\n구성요소 목록(SBOM) 생성',
        20: '취약점·수정 버전을 조회하고\n지원 종료일·영향 자산 연결',
        19: '담당자·기한·상태를 지정하고\n처리 내용과 변경 이력 기록',
        21: '동일 범위의 전후 결과 비교\n고객 보고용 PDF·JSON 제공',
    },
    4: {
        10: '추진 계획과 산출물',
        11: '요구사항을 정하고, 개발·시범 검증을 거쳐 결과물 제공',
        20: '추진 계획',
        21: '예상 산출물',
        12: '설계: 점검 대상·수집 범위·담당자 업무·보고 항목 정의\n개발: 자산 연결·취약점 분석·조치 관리·비교 보고 기능 구현\n검증: 합의한 시범 대상에서 분석·조치 기록·보고서 확인',
        13: '웹 시제품: 고객사 자산·위험 현황·조치 작업목록\n보고 자료: 구성요소 목록과 조치 전후 비교 보고서\n운영 자료: 소스 코드·설치 구성·사용 및 백업·복구 안내',
    },
}

# Cover geometry remains unchanged; its wording identifies this as a proposal.
cover = xml(parts['ppt/slides/slide1.xml'])
replace_text(cover, 2, '시스원 유지관리·공개SW 기술지원 업무를 위한 프로젝트 제안')
replace_text(cover, 4, '고객사 자산의 취약점·지원 종료·조치를\n한곳에서 관리하는 웹 서비스 개발 제안')
parts['ppt/slides/slide1.xml'] = encode(cover)

for target, base in ((2, 3), (3, 7), (4, 4)):
    import_slide(target, base)

NOTES = {
    1: '''이 자료는 프로젝트 착수 전에 시스원에 제안하는 요약서입니다. 표지를 포함해 총 4장이며, 앞으로 개발할 목적과 범위, 추진 방법과 예상 산출물을 설명합니다.
EOLWatch는 고객사 서버·프로젝트의 소프트웨어 구성요소, 취약점, 지원 종료 일정과 담당자의 조치 이력을 연결하는 웹 서비스로 제안합니다.
시스원의 공개 사업 소개에 있는 시스템통합 유지관리 및 공개SW 기술지원 업무를 활용 대상으로 설정했습니다. 회사 내부의 업무 방식이나 현재 시스템의 부족을 확인한 사실로 단정하지 않습니다.
사업 범위 참고: https://www.sysone.co.kr/businesses_veiw.php?idx=6 및 https://www.sysone.co.kr/businesses.php
본 요약서는 구현 완료 보고나 실제 기업 도입 성과를 제시하는 자료가 아닙니다.''',
    2: '''제안 배경은 유지관리 담당자가 수행하는 업무입니다. 취약점 공지가 나오면 어떤 고객사·서버를 확인할지 파악하고, 지원 종료 시점에 맞춰 변경 계획을 검토하며, 조치 후에는 고객에게 처리 근거를 설명해야 합니다.
이를 지원하기 위해 자산 정보와 소프트웨어 분석 결과, 담당자의 작업 이력을 연결하는 서비스를 개발하고자 합니다. 시스원이 현재 이 정보를 수작업이나 엑셀로 관리한다는 주장을 전제하지 않습니다.
기대 효과는 영향 대상 파악, 교체·업그레이드 계획 검토, 담당자 간 인계 및 고객 보고 지원입니다. 시간 절감률·비용 절감액과 같은 정량 효과는 아직 측정한 성과로 제시하지 않습니다.
지원 종료 정보는 공식 출처와 확인 시점을 함께 관리하는 방향으로 설계하고, 사용자의 입력·검토 범위와 분석 대상은 요구사항 단계에서 정할 계획입니다.''',
    3: '''다음 네 기능을 핵심 개발 범위로 제안합니다.
첫째, 허용된 서버 경로나 프로젝트 파일을 분석해 소프트웨어 구성요소와 버전을 목록으로 만들고 고객사·자산에 연결할 계획입니다. SBOM은 소프트웨어 구성요소 명세서입니다.
둘째, 알려진 취약점과 수정 버전을 조회하고 지원 종료 일정 및 영향 자산을 함께 확인하도록 개발할 계획입니다. EOL은 제품이나 소프트웨어의 지원 종료를 의미합니다.
셋째, 담당자·기한·진행 상태, 처리 내용과 변경 이력을 남겨 조치 업무를 관리하도록 할 계획입니다.
넷째, 담당자가 조치한 뒤 같은 범위를 다시 분석해 전후 변화를 비교하고, 고객 보고에 활용할 PDF·JSON 자료를 생성할 계획입니다.
구성요소 식별과 취약점 대조에는 Syft·Grype 등 공개 도구를 활용하고, 자산 연결·업무 이력·전후 비교·보고 기능을 중심으로 개발할 계획입니다. 실제 업데이트와 조치 완료 판단은 담당자가 수행하도록 설계합니다.''',
    4: '''추진은 설계, 개발, 시범 검증의 세 단계로 계획합니다. 구체적인 기간은 적용 범위와 요구사항을 확인한 뒤 조정할 예정이며 이 요약서에서 일정 합의나 기업 적용을 확정한 것으로 표현하지 않습니다.
설계 단계에서는 점검 대상, 서버 접근 권한, 수집 범위와 주기, 담당자 업무, 고객 보고 항목, 자료 보관 기준을 확인하고 기능 범위를 정할 계획입니다.
개발 단계에서는 웹 화면·API·데이터 저장소를 구성하고 자산 연결, 소프트웨어 분석, 담당자 조치 기록과 전후 비교 보고 기능을 구현할 계획입니다. React·FastAPI·PostgreSQL 및 Docker 기반의 실행 구성을 검토합니다.
검증 단계에서는 합의한 시범 대상에서 자산과 분석 결과가 정확히 연결되는지, 조치 기록과 보고 항목이 업무에 적합한지 확인하고 보완할 계획입니다. 실제 고객사 접근이나 도입이 확정됐다는 의미는 아닙니다.
예상 산출물은 웹 시제품, 구성요소 목록과 조치 전후 비교 보고서, 소스 코드와 설치·사용·백업·복구 안내입니다. 기업 담당자가 결과물을 확인하고 향후 적용 여부를 검토할 수 있도록 제공하는 것이 목표입니다.''',
}

# Replace ALL notes, removing the former completion report and measured results.
for number, text in NOTES.items():
    rels = xml(parts[f'ppt/slides/_rels/slide{number}.xml.rels'])
    rel = next(r for r in rels if r.get('Type').endswith('/notesSlide'))
    path = posixpath.normpath(posixpath.join('ppt/slides', rel.get('Target')))
    root = xml(parts[path])
    body = root.xpath('.//p:sp[p:nvSpPr/p:nvPr/p:ph[@type="body"]]/p:txBody', namespaces=NS)[0]
    for paragraph in list(body.findall('a:p', NS)):
        body.remove(paragraph)
    for line in text.split('\n'):
        paragraph = E.SubElement(body, f'{{{NS["a"]}}}p')
        run = E.SubElement(paragraph, f'{{{NS["a"]}}}r')
        E.SubElement(run, f'{{{NS["a"]}}}t').text = line
    parts[path] = encode(root)

ct = xml(parts['[Content_Types].xml'])
known = {el.get('Extension') for el in ct if E.QName(el).localname == 'Default'}
for item in xml(template['[Content_Types].xml']):
    if E.QName(item).localname == 'Default' and item.get('Extension') not in known:
        ct.append(deepcopy(item))
parts['[Content_Types].xml'] = encode(ct)

core = xml(parts['docProps/core.xml'])
for key, text in {
    '{http://purl.org/dc/elements/1.1/}title': 'EOLWatch 프로젝트 제안 요약서',
    '{http://purl.org/dc/elements/1.1/}subject': '시스원에 제안하는 착수 전 개발 목적·기능·추진 계획·예상 산출물',
}.items():
    el = core.find(key)
    if el is None:
        el = E.SubElement(core, key)
    el.text = text
parts['docProps/core.xml'] = encode(core)

with ZipFile(OUT, 'w', ZIP_DEFLATED) as z:
    for name, data in parts.items():
        z.writestr(name, data)
check = Presentation(OUT)
assert len(check.slides) == 4, 'Cover must be INCLUDED in four slides.'
with ZipFile(OUT) as z:
    assert z.testzip() is None
for path in (SOURCE, BASE):
    assert sha(path) == hashes[str(path)]
content = [{'slide': n, 'text': [sh.text for sh in s.shapes if sh.has_text_frame and sh.text],
            'notes': s.notes_slide.notes_text_frame.text}
           for n, s in enumerate(check.slides, 1)]
visible = '\n'.join(t for page in content for t in page['text'])
for banned in ('Jinja2', '검증일', '미검출', '실제 검증', 'LAB-VM', '3.1.4', '구현 완료'):
    assert banned not in visible, banned
(WORK / 'content_review.json').write_text(json.dumps(content, ensure_ascii=False, indent=2))
(WORK / 'validation.json').write_text(json.dumps({
    'source': str(SOURCE), 'base': str(BASE), 'output': str(OUT),
    'slides_including_cover': 4, 'purpose': 'pre-project proposal to SysOne',
    'base_slide_mapping': {'2': 3, '3': 7, '4': 4},
    'original_hashes': hashes, 'sources_unchanged': True,
    'all_speaker_notes_rewritten': True, 'completed_results_removed': True,
}, ensure_ascii=False, indent=2))
print(OUT)
print('Validated: exactly 4 slides including cover; proposal wording and notes; original template reused.')
