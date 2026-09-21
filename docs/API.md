# EOLWatch API 안내

기준일: 2026-09-21. `backend/app/main.py`에 등록된 라우터와 코드를 읽어 정리했다. 구현 진행에 따라 실제 OpenAPI가 우선한다. 2026-09-18 재범위화에서 고객·사이트·제품·계약·소프트웨어·EOL 카탈로그·알림·EOL/점검/자산 PDF·CSV 등록·위험도 이력·구성요소 지원종료 수정 API는 제거했다.

## 접속과 권한

- 실제 시연 API: `http://127.0.0.1:18080/api` — 관리 VM의 시연 DB.
- 맥 개발 API: `http://127.0.0.1:8000/api` — 별도 DB.
- 맥 대화형 명세: <http://127.0.0.1:8000/docs>, JSON 명세: <http://127.0.0.1:8000/openapi.json>.
- 공개 상태 확인: `GET /health`. 로그인 외 `/api/` 요청은 Bearer 토큰이 필요하다.
- VIEWER는 조회·비교·PDF/JSON 다운로드를 사용할 수 있다. 서버 등록·검사 요청·조치 기록과 사용자·감사 로그 조회는 ADMIN 전용이다.

인증은 미들웨어에서 검사하므로 OpenAPI 응답 목록에 없는 401·403도 반환할 수 있다. 비교·보고서 GET은 VEX를 변경하지 않는다. 로그인은 마지막 로그인 시각과 감사 로그를 기록한다. 아래 "로그인"은 ADMIN 또는 VIEWER를 뜻한다. 페이지 응답은 `items`, `total`, `limit`, `offset`을 포함한다.

## 1. 개발 검사 — 소스 ZIP

| 방식 | 경로 | 권한 | 용도·query |
|---|---|---|---|
| POST | `/api/analyses/assets/{asset_id}/uploads` | ADMIN | 소스 ZIP 업로드와 검사 요청 · multipart `file`, `project_name` |
| GET | `/api/analyses/uploads` | 로그인 | 보관된 ZIP 페이지 · `asset_id`, `scan_scope`, `limit`(1~100), `offset` |
| GET | `/api/analyses/uploads/{upload_id}/raw` | 로그인 | SHA-256 검증 후 원본 ZIP 다운로드 |
| POST | `/api/analyses/uploads/{upload_id}/jobs` | ADMIN | 저장된 ZIP으로 재검사 |
| GET | `/api/analyses/storage` | ADMIN | ZIP 보관소 현황(파일 수·바이트·미참조·누락·임시 파일) |

검사 작업 공통 API는 개발·인프라 두 축이 함께 쓴다.

| 방식 | 경로 | 권한 | 용도·query |
|---|---|---|---|
| GET | `/api/analyses/jobs` | 로그인 | 최근 검사 작업 100건 |
| GET | `/api/analyses/jobs/active` | 로그인 | 대기·실행·취소 요청 상태의 모든 작업 |
| GET | `/api/analyses/jobs/{job_id}` | 로그인 | 작업 단건 조회 |
| POST | `/api/analyses/jobs/{job_id}/retry` | ADMIN | 실패한 작업 재시도 · 이전 입력 유지 |
| POST | `/api/analyses/jobs/{job_id}/cancel` | ADMIN | 취소 요청 |

## 2. 인프라 검사 — 서버

| 방식 | 경로 | 권한 | 용도·query |
|---|---|---|---|
| GET | `/api/assets` | 로그인 | 서버 목록 · `q`(번호·이름·IP·SSH 계정), `asset_type` |
| POST | `/api/assets` | ADMIN | 서버 등록 |
| GET | `/api/assets/{asset_id}` | 로그인 | 서버 상세 |
| PATCH | `/api/assets/{asset_id}` | ADMIN | 서버 수정 |
| DELETE | `/api/assets/{asset_id}` | ADMIN | 서버 삭제 |
| GET | `/api/assets/{asset_id}/timeline` | 로그인 | 검사 작업·SSH 점검·SBOM 저장·CVE 조치 통합 타임라인 |
| GET | `/api/checks` | 로그인 | SSH 점검(서버 정보 수집) 이력 · `asset_id`, `limit`(1~500) |
| POST | `/api/checks/assets/{asset_id}/run` | ADMIN | SSH 점검 실행 · CPU·메모리·디스크·프로세스·설치 패키지·OS·서버 정보 수집 |
| GET | `/api/checks/{job_id}/result` | 로그인 | 점검 결과 · `raw_metrics.server_info`에 호스트·커널·CPU 모델·메모리 총량·디스크 총량·가상화·DMI·클라우드·IP·수신 포트·실행 서비스 |
| POST | `/api/checks/{job_id}/sbom` | ADMIN | 성공한 점검의 패키지 목록에서 자체 SPDX 생성 |
| POST | `/api/analyses/assets/{asset_id}/jobs` | ADMIN | 서버 취약점 검사 요청 · JSON `scan_scope`, `target_path` |
| GET | `/api/analyses/schedules` | 로그인 | 정기 검사 예약 목록 |
| POST | `/api/analyses/schedules` | ADMIN | 정기 검사 예약 생성 |
| PATCH | `/api/analyses/schedules/{schedule_id}` | ADMIN | 예약 주기·활성 상태 수정 |

서버 필드는 `asset_tag`, `name`, `asset_type`(`server`, `storage`, `network`, `security`, `vm`, `cloud`, `other`), `ip_address`, `ssh_port`, `ssh_username`, `monitored`다. 응답에는 `sbom_count`, `vulnerability_counts`(심각도별), `vulnerability_count`가 붙는다. 건물·랙·구매가·담당자 같은 재고 필드는 없다.

## 3. 검사 기록

| 방식 | 경로 | 권한 | 용도·query |
|---|---|---|---|
| GET | `/api/analyses` | 로그인 | 최근 검사 결과 100건 |
| GET | `/api/analyses/history` | 로그인 | 모든 성공 검사 페이지 · `asset_id`, `scan_scope`, `q`, `date_from`, `date_to`, `limit`, `offset` |
| GET | `/api/analyses/job-history` | 로그인 | 작업 이력 페이지 · 위 필터와 `status` |
| GET | `/api/analyses/projects` | 로그인 | 서버·범위별 프로젝트 요약 · `asset_id`, `scan_scope`, `q`, 페이지 |
| GET | `/api/analyses/runs/{run_id}` | 로그인 | 원본 JSON을 제외한 검사 메타데이터 |
| GET | `/api/analyses/runs/{run_id}/candidates` | 로그인 | 같은 서버·범위의 이후 검사 후보 · `limit`, `offset` |
| GET | `/api/analyses/{base_id}/compare/{target_id}` | 로그인 | 검사 원본 전후 비교 |
| GET | `/api/analyses/{run_id}/bundle` | 로그인 | 해당 검사의 SPDX·Grype 원본 |
| POST | `/api/analyses/import` | ADMIN | SPDX·Grype 묶음 반입 (API 전용, 화면 없음) |
| GET | `/api/reports/analyses/{base_id}/compare/{target_id}.json` | 로그인 | 비교 JSON 다운로드 |
| GET | `/api/reports/analyses/{base_id}/compare/{target_id}.pdf` | 로그인 | 비교 PDF 다운로드 |
| GET | `/api/sboms` | 로그인 | SBOM(의존성 목록) 목록 |
| POST | `/api/sboms/import` | ADMIN | SPDX·CycloneDX 반입 · query `asset_id` (API 전용, 화면 없음) |
| GET | `/api/sboms/{base_sbom_id}/compare/{target_sbom_id}` | 로그인 | 구성요소 목록 차이 |
| GET | `/api/sboms/{sbom_id}/detail` | 로그인 | SBOM 상세·서버·연결 검사 ID |
| GET | `/api/sboms/{sbom_id}/raw` | 로그인 | 원본 JSON 다운로드 |
| GET | `/api/sboms/{sbom_id}/component-page` | 로그인 | 구성요소 서버 페이지 · `q`, `limit`(1~200), `offset` |
| GET | `/api/sboms/{sbom_id}/dependencies` | 로그인 | 의존관계 페이지 · `component_id`, `direction`, `limit`, `offset` |
| GET | `/api/sboms/{sbom_id}/components/{component_id}` | 로그인 | 구성요소 상세 |
| GET | `/api/sboms/{sbom_id}/components` | 로그인 | 구성요소 목록 · `q` |
| GET | `/api/vulnerabilities` | 로그인 | 구성요소·CVE·VEX 조회 · `sbom_id`, `vex_status` |
| POST | `/api/vulnerabilities/scan/sbom/{sbom_id}` | ADMIN | OSV 직접 조회(교차 검증) |
| GET | `/api/vulnerabilities/{link_id}` | 로그인 | 개별 CVE 연결의 현재 조치 상태 |
| PATCH | `/api/vulnerabilities/{link_id}/vex` | ADMIN | 수동 VEX 상태 변경 |
| POST | `/api/vulnerabilities/{link_id}/actions` | ADMIN | 담당자·기한·조치 내용·재검사 근거 기록 |
| GET | `/api/vulnerabilities/{link_id}/actions` | 로그인 | 조치 이력 · `limit`, `before_id` |
| GET, HEAD | `/api/vulnerability-work` | 로그인 | 조치 작업목록 서버 페이지 |
| GET | `/api/dashboard/summary` | 로그인 | 개요 요약 |

`/api/dashboard/summary` 필드는 `assets`, `sbom_documents`, `components`, `dependencies`, `open_cves`, `affected_assets`, `current_open_cves`, `current_affected_assets`, `failed_checks_24h`, `sbom_quality`, `latest_analyses`다. `open_cves`·`affected_assets`는 전체 보관 이력 기준, `current_*`는 서버·범위별 최신 성공 SBOM 기준이다.

## 4. 인증·관리

| 방식 | 경로 | 권한 | 용도·query |
|---|---|---|---|
| POST | `/api/auth/login` | 공개 | 로그인·토큰 발급 |
| GET | `/api/auth/me` | 로그인 | 현재 사용자 |
| GET | `/api/auth/users` | ADMIN | 사용자 목록 |
| POST | `/api/auth/users` | ADMIN | 사용자 생성 (`ADMIN`/`VIEWER`) |
| PATCH | `/api/auth/users/{user_id}` | ADMIN | 역할·활성 상태·비밀번호 변경 |
| GET | `/api/auth/audit-logs` | ADMIN | 감사 로그 · `limit` |
| GET | `/health` | 공개 | API 상태 확인 |

## 5. 로그인과 조회 예시

```bash
curl --fail-with-body -X POST http://127.0.0.1:18080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<실습 비밀번호>"}'
```

응답의 `access_token`을 사용한다. 아래 명령의 변수는 실습 터미널에서 설정하며 문서·보고서에 실제 토큰을 붙이지 않는다.

```bash
EOLWATCH_TOKEN='<로그인 응답의 access_token>'
curl --fail-with-body -H "Authorization: Bearer $EOLWATCH_TOKEN" \
  http://127.0.0.1:18080/api/analyses/jobs
```

## 6. 개발 검사 요청

```bash
curl --fail-with-body -X POST \
  http://127.0.0.1:18080/api/analyses/assets/1/uploads \
  -H "Authorization: Bearer $EOLWATCH_TOKEN" \
  -F 'project_name=주문 API' -F 'file=@/절대/경로/source.zip;type=application/zip'
```

ZIP은 별도 endpoint를 사용하며 일반 jobs 본문에 `source-zip`을 보내지 않는다. 결과를 연결할 서버(`asset_id`)가 필요하지만 그 서버로 SSH 접속하지는 않는다. 프로젝트명은 1~80자로 문자·숫자·공백·점·밑줄·하이픈을 허용하고 첫 문자는 문자·숫자·밑줄이어야 한다. 원본은 SHA-256으로 보관한다. 기본 한도는 업로드 50 MiB, 해제 합계 250 MiB, 개별 파일 32 MiB, 20,000항목, 압축률 100배다. 경로 이탈·중복·링크·특수 파일·암호화·지원하지 않는 압축은 거부한다. 업로드 크기 초과는 **413**, 잘못된 ZIP은 **422**다. 저장 범위는 `source-zip:<프로젝트명>`이다.

- 정상 접수는 **202**이며 작업 ID·상태를 반환한다. 완료 후 `analysis_run_id`·`sbom_id`로 결과를 확인한다.
- 같은 서버·같은 범위·같은 ZIP 해시의 활성 요청은 기존 작업을 반환한다. 다른 활성 입력은 **409**다.
- 상태는 `QUEUED`, `COLLECTING`, `SCANNING`, `IMPORTING`, `CANCEL_REQUESTED`, `CANCELLED`, `SUCCESS`, `FAILED`다.
- 재시도는 실패한 작업만 허용하며 이전 입력을 유지한다. ZIP은 보관한 원본의 해시·크기를 검증한 뒤 사용한다.

## 7. 인프라 검사 요청과 정기 검사

```bash
curl --fail-with-body -X POST \
  http://127.0.0.1:18080/api/analyses/assets/1/jobs \
  -H "Authorization: Bearer $EOLWATCH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scan_scope":"ubuntu-dpkg-installed"}'
```

| `scan_scope` 입력 | 추가 필드 | 의미 | 화면 |
|---|---|---|---|
| `ubuntu-dpkg-installed` | 없음 | Ubuntu dpkg 설치 패키지, 본문 생략 시 기본값 | 인프라 검사 |
| `demo-python-venv` | 없음 | 고정 `~/eolwatch-demo/.venv` | 인프라 검사 |
| `ssh-python-environment` | `target_path` | 절대 경로의 설치 Python 메타데이터 | API 전용 |
| `ssh-project-directory` | `target_path` | 절대 경로의 프로젝트 자료 | API 전용 |

경로는 `/` 이외의 절대 디렉터리로 정규화하며 `..`·제어 문자·220자를 넘는 정규화 경로를 거부한다. 경로 프로필의 저장 범위는 `<프로필>:<정규화 경로>`다. 서버에는 검사 대상 설정(`monitored`)·IP·SSH 계정이 필요하고 키·호스트 키는 관리 서버에 설정한다. 임의 명령·개인키·허용하지 않은 필드는 받지 않는다.

정기 검사 예약 본문:

```json
{
  "asset_id": 1,
  "scan_scope": "ubuntu-dpkg-installed",
  "interval_minutes": 1440,
  "enabled": true
}
```

`POST /api/analyses/schedules`는 **201**이며 `interval_minutes` 범위는 5~525600이다. 같은 서버·범위의 중복 예약은 **409**다. ZIP 예약은 지원하지 않는다. `PATCH /api/analyses/schedules/{id}`로 주기와 `enabled`를 수정하며 명시적 null·추가 필드는 거부한다. 예약은 현재 화면 메뉴에 없고 API로 제공하는 추가 서비스다.

`/api/checks/...`는 SSH로 서버 정보를 수집하는 흐름이다. Syft·Grype 취약점 검사(`/api/analyses/...`)와 별개이며, 성공한 점검의 패키지 목록에서 자체 SPDX를 만들 수 있다.

## 8. 원본 반입과 결과 조회

`POST /api/analyses/import` 본문은 다음 구조다. 화면은 없고 스크립트(`scripts/analyze-lab.py`)와 API에서 쓴다.

```json
{
  "asset_id": 1,
  "scan_scope": "수집 범위를 명시한 문자열",
  "sbom": {"spdxVersion": "SPDX-2.3", "...": "완전한 SPDX 원본"},
  "report": {"descriptor": {"name": "grype", "version": "..."}, "source": {}, "matches": []}
}
```

위 코드는 구조 설명용이며 그대로 반입 가능한 원본은 아니다. 실제 요청은 완전한 SPDX 2.3과 Grype JSON이어야 한다. 구성요소가 없는 SBOM, 필수 `matches`가 없는 보고서, SBOM과 맞지 않는 보고서는 거부한다. 유효한 SBOM에 명시적인 `matches: []`는 정상 검사 0건이 될 수 있다. 동일한 서버·SBOM·보고서 묶음은 기존 이력을 반환한다.

`POST /api/sboms/import`는 SPDX 2.3과 CycloneDX 1.4~1.7을 받고 query의 `asset_id`로 서버에 연결한다.

- `GET /api/analyses/{run_id}/bundle`: `asset_id`, `scan_scope`, `sbom`, `report` 원본.
- `GET /api/vulnerability-work?sbom_id=12&status=ALL&limit=100&offset=0`: 선택 SBOM의 서버 페이지 CVE 조회.
- `GET /api/vulnerabilities?sbom_id=12`: 기존 호환 전체 목록이며 페이지 매개변수가 없다. 현재 웹은 큰 CVE 목록을 이 경로로 전수 다운로드하지 않는다.
- `GET /api/sboms/{id}/component-page`: `{items,total,limit,offset}`. 검색은 패키지 이름·버전·PURL·CPE·공급자, 기본 50행이다.
- `GET /api/sboms/{id}/dependencies`: 기본 50행, 최대 200행. `direction=both|outgoing|incoming`; `component_id`는 같은 SBOM에 속해야 하며 불일치는 404다.
- 구성요소 상세는 라이선스·해시·PURL·CPE·`product_release_id`를 포함한다. 지원 종료일 필드는 제거했다.

## 9. 검사 전후 비교와 보고서

```bash
curl --fail-with-body -H "Authorization: Bearer $EOLWATCH_TOKEN" \
  http://127.0.0.1:18080/api/analyses/3/compare/4
curl --fail-with-body -H "Authorization: Bearer $EOLWATCH_TOKEN" \
  -o eolwatch-analysis-3-4.pdf \
  http://127.0.0.1:18080/api/reports/analyses/3/compare/4.pdf
curl --fail-with-body -H "Authorization: Bearer $EOLWATCH_TOKEN" \
  -o eolwatch-analysis-3-4.json \
  http://127.0.0.1:18080/api/reports/analyses/3/compare/4.json
```

#3 → #4는 관리 VM의 저장된 데모 앱 이력이다. 맥 DB나 재실행한 결과에 같은 번호를 가정하지 않는다.

비교는 같은 서버·명시된 동일 범위·이전→이후 순서만 허용한다. `findings`의 단위는 구성요소 식별자+CVE이며 상태는 `PERSISTENT`, `NEW`, `NO_LONGER_DETECTED`, `COMPONENT_REMOVED`다. 수정 버전과 전후 설치 버전 집합을 함께 반환한다.

수동 반입·검사 도구/DB 차이·식별 정보 부족은 `warnings`와 `comparable: false`로 알린다. 이는 조회를 막는 조건과 구분된다. 다른 서버·범위·순서는 **409**, 이력 없음은 **404**, 잘못된 원본은 **422**다. 보고서 생성은 원본 해시가 저장된 값과 다르면 **409**다.

PDF·JSON에는 검사·작업·서버·범위·도구·해시·비교 결과·제한과 원본 조회 경로가 포함된다. `Content-Disposition: attachment`와 `Cache-Control: no-store`로 반환하며 수동 VEX를 바꾸지 않는다. 상세 응답은 [비교 보고서 안내](COMPARISON_REPORTS.md)를 따른다.

`/api/sboms/{base_sbom_id}/compare/{target_sbom_id}`는 구성요소 목록 차이 기능이다. 동일 패키지의 여러 버전·중복 설치를 보존하고 명확한 대응만 변경으로 묶으며, 모호한 여러 버전 전환은 추가·제거로 반환한다. `unchanged_count`는 구성요소 발생 건수다. 조치 시연에는 서버·범위·원본 근거를 확인하는 **검사 비교 API**를 사용한다.

## 10. 담당자·기한·조치 이력

`GET /api/vulnerabilities/{link_id}`로 현재 `review_revision`을 읽고 다음 요청에 넣는다.

```json
{
  "expected_revision": 0,
  "status": "UNDER_INVESTIGATION",
  "detail": "업데이트 일정과 담당자를 확인했습니다.",
  "assignee_id": 2,
  "due_date": "2026-10-01"
}
```

`POST /api/vulnerabilities/{link_id}/actions`는 로그인한 관리자에서 작성자를 결정한다. 클라이언트가 작성자·증거 원본을 직접 지정할 수 없다. `expected_revision`은 0 이상, `detail`은 공백을 제거한 1~2000자, 담당자는 존재하는 활성 계정이어야 한다. 지정한 사용자가 VIEWER여도 담당자로 연결할 수 있지만 조치 쓰기 권한이 생기는 것은 아니다.

응답은 갱신된 CVE 연결에 `review_revision`, `assignee_id`, `assignee_username`, `due_date`를 포함한다. 같은 이전 버전의 요청이 경합하면 한 건만 반영되고 나머지는 **409**다. 현재 상태·전후 스냅샷·작성자·도메인 감사 로그를 한 트랜잭션으로 저장한다. 선택 필드의 생략은 현재 값을 유지하고 명시적 `null`은 값을 지운다.

`evidence_analysis_run_id`에 이후 검사 ID를 넣으면 해당 CVE·구성요소·이전 버전에 맞는 비교 근거를 첨부한다. 다른 서버·범위·기준 검사·잘못된 해시는 거부한다. 첨부 결과가 `PERSISTENT` 또는 `NEW`인데 `FIXED`를 요청하면 **409**다. 유효한 미검출 근거를 첨부해도 자동 검증·승인이 아니며 수동 결정으로 기록한다. 근거 없는 `FIXED`도 메모를 요구하고 `manual_without_analysis`로 구분한다.

`GET /api/vulnerabilities/{link_id}/actions?limit=100&before_id=...`는 최신 ID부터 `items`, `has_more`, `next_before_id`를 반환한다. `limit`은 1~100이다. 작성 당시 사용자 이름과 근거 스냅샷을 보관하며 이후 이름·원본이 달라져도 기존 이력을 다시 계산하지 않는다.

화면·판단 기준·검증 범위는 [조치 이력 안내](VULNERABILITY_ACTIONS.md)를 따른다.

## 11. 수동 VEX와 OSV 교차 검증

`PATCH /api/vulnerabilities/{link_id}/vex`의 필수 입력은 `status`다. 허용 값은 `AFFECTED`, `NOT_AFFECTED`, `FIXED`, `UNDER_INVESTIGATION`이며 `justification`, `response`, `detail`을 함께 남길 수 있다. 이 경로도 같은 조치 서비스로 상태·이력을 함께 저장한다. `expected_revision`을 제공하면 경합을 검사하고, 생략하면 잠근 최신 버전을 사용한다. 메모 생략은 `legacy_vex`, `note_provided: false`로 이력에 표시하고 기존 현재 메모는 유지한다. 미검출 결과만으로 자동 호출하지 않는다.

OSV 직접 조회는 PURL 생태계·이름·설치 버전이 맞는 advisory만 연결한다. PyPI PEP440, 명시적 SEMVER, npm·Go·Cargo SemVer 순서를 지원하며 미지원 순서/Git 그래프의 수정 버전은 추정하지 않는다. 여러 advisory의 동일 CVE는 별칭·참조·심각도 최댓값으로 병합하고 다른 advisory에서 여전히 취약한 수정 후보는 제외한다. CVSS 2/3/4는 라이브러리로 계산하고 유효한 정보가 없으면 UNKNOWN이다.

응답은 기존 건수와 `skipped_components`(식별 PURL/설치 버전 없음), `ignored_withdrawn`, `ignored_unaffected`를 포함한다. 모든 batch 페이지와 상세 응답을 확인하며 개수 불일치·잘못된 응답·외부 실패는 **502**다. 철회나 조회 미검출만으로 기존 기록·사람의 검토를 삭제하거나 자동 FIXED하지 않는다. OSV 재조회가 기존 Grype 연결의 검사 ID·수정 버전 등 근거를 덮어쓰지 않도록 구분하며 새 OSV 연결은 저장할 수 있다. 전체 모델·입력 필드는 [데이터 모델](DATA_MODEL.md)과 실제 OpenAPI를 확인한다.

## 12. 조치 작업목록과 서버 페이지

`GET /api/vulnerability-work`와 HEAD를 지원한다. 기본 대상은 **전체 SBOM 이력의 미완료 조치**다.

| query | 값·기본값 |
|---|---|
| `status` | OPEN(기본), ALL, AFFECTED, UNDER_INVESTIGATION, FIXED, NOT_AFFECTED |
| `q` | CVE·패키지·서버 번호/이름 검색, 최대 200자 |
| `asset_id`, `sbom_id` | 선택 서버·SBOM, 1 이상. 없는 SBOM은 404 |
| `severity` | UNKNOWN, NONE, LOW, MEDIUM, HIGH, CRITICAL |
| `assignee_id` | 담당자 ID, 1 이상 |
| `unassigned` | 미지정만, 기본 false |
| `overdue` | 기한이 지난 미완료 조치만, 기본 false |
| `limit`, `offset` | 기본 25/0, limit 1~100, offset 0 이상 |

담당자와 미지정을 동시에 지정하거나 완료 상태와 기한 초과를 함께 지정하면 **422**다. 정렬은 미완료 기한 초과 → 심각도 높은 순 → 연결 ID 순이다. 오늘이 기한인 항목은 초과가 아니다.

응답은 `{items,total,limit,offset,as_of,scope}`이며 `scope`는 `ALL_SBOM_HISTORY`다. 각 항목은 기존 CVE 응답과 `asset_id`, `overdue`를 포함한다. 이전 SBOM의 미완료 조치를 새 검사 때문에 숨기지 않는다. count와 페이지를 DB에서 계산하며 원본 SBOM·Grype JSON은 읽지 않는다.

전체 구현과 실제 검증의 구분은 [구현 현황](IMPLEMENTATION_STATUS.md)을 확인한다.
