# 분석 전후 검증 보고서

선택한 두 분석의 CVE 변화와 근거를 **PDF 보고서 또는 JSON 데이터**로 내려받는다. 저장된 원본으로 생성하며 새 분석, 패치 또는 VEX 상태 변경을 실행하지 않는다.

## 웹에서 사용

1. 관리 VM의 <http://127.0.0.1:18080>에 로그인한다.
2. `CVE 조치` → `분석 전후 비교`에서 같은 서버·같은 범위의 이전/이후 분석을 선택한다.
3. `분석 전후 비교`를 누르고 결과와 주의사항을 확인한다.
4. `검증 보고서 PDF` 또는 `검증 데이터 JSON`을 누른다.

현재 저장된 시연 결과는 이전 **분석 #3 / SBOM #12**, 이후 **분석 #4 / SBOM #13**이다. 대상은 LAB-VM-01의 `demo-python-venv`이며, Jinja2 3.1.4 → 3.1.6과 CVE 3건 → 0건을 확인했다. [실제 조치 검증 기록](archive/REMEDIATION_VERIFICATION_2026-09-15.md)을 참고한다.

관리자와 조회자가 모두 보고서를 받을 수 있다. 로그인은 필요하다. 다운로드 중 분석 선택을 바꾸거나 화면을 나가면 진행 중인 다운로드를 취소하며, 이전 선택의 파일을 뒤늦게 저장하지 않는다.

## 보고서 내용

- 자산, 분석 범위, 이전/이후 분석 ID·SBOM ID와 저장 시각
- 구성요소 수·고유 CVE 수, 계속 검출·새로 검출·재분석 미검출·구성요소 제거 수
- 모든 비교 행의 CVE, 패키지 식별자, 이전/이후 설치 버전, 도구가 제시한 수정 버전, 심각도
- Syft·Grype 정보, 취약점 DB 기준, 연결된 성공 작업과 요청·시작·완료 시각
- SBOM·분석 묶음의 SHA-256, 원본 조회 경로와 비교 조건 주의사항
- 해석 범위와 한계

웹 표가 100개씩 보여주더라도 보고서는 **비교 결과 전체**를 포함한다. PDF는 한글 글꼴을 포함하고 여러 페이지로 나눈다. JSON에는 `report_version`, `generated_at`, `findings_sha256`, 해시 계산 방식도 포함한다. `generated_at`은 보고서를 만든 시각이며 분석 실행 시각과 구분한다.

성공한 작업의 자산명·태그가 있으면 당시 요청에 저장된 값을 사용한다. 수동 반입 등 해당 기록이 없는 경우에는 현재 자산 원장 값을 사용하고 `asset_identity_source`로 출처를 구분한다. SSH 개인키, worker 토큰과 임의 도구 설정은 보고서에 넣지 않는다.

## 비교 조건과 원본 검증

- 다른 자산·범위, 동일 분석 또는 거꾸로 된 시간 순서는 비교와 다운로드를 거부한다.
- 잘못된 SBOM·Grype 원본은 정상 0건으로 보고하지 않는다.
- 보고서 생성 시 저장된 원본으로 해시를 다시 계산한다. 분석 등록 때의 값과 다르면 HTTP 409로 거부한다.
- 도구·DB 정보 차이, 수동 반입, 식별 정보 부족 등의 경우에는 탐지 변화와 주의사항을 함께 출력한다. `comparable=false`는 조건 확인이 필요하다는 뜻이며 관측 결과를 숨기지 않는다.
- 재분석 미검출은 조치 완료 승인이나 실제 악용 가능성의 판정이 아니다. 설치 버전과 실제 서비스 동작, 해당 취약점의 영향 조건을 별도로 확인한다.

## API

| 요청 | 응답 |
|---|---|
| `GET /api/reports/analyses/{base_id}/compare/{target_id}.pdf` | 한글 PDF 첨부 파일 |
| `GET /api/reports/analyses/{base_id}/compare/{target_id}.json` | 검증 데이터 JSON 첨부 파일 |
| `GET /api/analyses/{run_id}/bundle` | 해당 분석의 원본 SPDX와 Grype 묶음 |

보고서 응답은 `Cache-Control: no-store`를 사용한다. 다운로드 파일명은 `eolwatch-analysis-{base_id}-{target_id}.pdf` 또는 `.json`이다.

## SHA-256 계산 방식

원본 파일의 공백·들여쓰기와 무관하게 내용을 비교할 수 있도록 **정규화한 JSON**의 UTF-8 바이트를 해시한다. 내려받은 파일 전체를 그대로 해시한 값과는 다를 수 있다.

```python
import hashlib
import json

def digest(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

# bundle: 원본 묶음 GET 응답 / report: 검증 데이터 JSON
sbom_sha256 = digest(bundle["sbom"])
bundle_sha256 = digest({key: bundle[key] for key in ("asset_id", "sbom", "report")})
findings_sha256 = digest(report["findings"])
```

분석 묶음 해시의 대상 필드는 `asset_id`, `sbom`, `report`이며 `scan_scope`는 포함하지 않는다. 해시는 원본 내용의 일치를 확인하는 수단이다. 외부 작성자의 서명이나 수집 사실 자체의 암호학적 인증으로 해석하지 않는다.
