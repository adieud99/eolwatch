# EOLWatch API 안내

기준일: 2026-09-21. `backend/app/main.py`에 등록된 라우터와 코드를 읽어 정리했다. 구현 진행에 따라 실제 OpenAPI가 우선한다. 2026-09-18 재범위화에서 고객·사이트·제품·계약·소프트웨어·EOL 카탈로그·알림·EOL/점검/자산 PDF·CSV 등록·위험도 이력·구성요소 지원종료 수정 API는 제거했다.

## 접속과 권한

- 실제 시연 API: `http://127.0.0.1:18080/api` — 관리 VM의 시연 DB.
- 맥 개발 API: `http://127.0.0.1:8000/api` — 별도 DB.
- 맥 대화형 명세: <http://127.0.0.1:8000/docs>, JSON 명세: <http://127.0.0.1:8000/openapi.json>.
- 공개 상태 확인: `GET /health`. 로그인 외 `/api/` 요청은 Bearer 토큰이 필요하다.
- VIEWER는 조회·비교·PDF/JSON 다운로드를 사용할 수 있다. 서버 등록·검사 요청·조치 기록과 사용자·감사 로그 조회는 ADMIN 전용이다.

인증은 미들웨어에서 검사하므로 OpenAPI 응답 목록에 없는 401·403도 반환할 수 있다. 비교·보고서 GET은 VEX를 변경하지 않는다. 로그인은 마지막 로그인 시각과 감사 로그를 기록한다. 아래 "로그인"은 ADMIN 또는 VIEWER를 뜻한다. 페이지 응답은 `items`, `total`, `limit`, `offset`을 포함한다.

## 0. AI 요약 (선택 기능)

| 방식 | 경로 | 권한 | 용도 |
|---|---|---|---|
| GET | `/api/ai/status` | 로그인 | AI 사용 가능 여부, 제공자(`openai`/`anthropic`), 모델. 키가 있어야 `enabled: true` |
| GET | `/api/ai/analyses/{run_id}` | 로그인 | 검사 결과의 마지막 AI 요약 (없으면 `null`) |
| POST | `/api/ai/analyses/{run_id}` | ADMIN | 검사 결과의 CVE 목록을 압축해 AI에 보내 위험 수준·우선 조치·확인 사항을 한국어로 생성해 저장. 같은 데이터·모델이면 저장된 답을 재사용하고 `?force=true`로 다시 생성 |
| GET | `/api/ai/checks/{job_id}` | 로그인 | SSH 점검의 마지막 AI 요약 |
| POST | `/api/ai/checks/{job_id}` | ADMIN | 서버 정보·자원 사용률·포트·서비스를 압축해 AI에 보내 서버 진단을 생성해 저장 (`?force=true` 재생성) |

제공자는 `AI_PROVIDER`로 고른다. 기본 `openai`는 `OPENAI_API_KEY`와 `OPENAI_MODEL`(기본 `gpt-5-mini`, `OPENAI_BASE_URL`로 호환 서버 지정 가능), `anthropic`으로 바꾸면 `ANTHROPIC_API_KEY`와 `AI_MODEL`(기본 `claude-opus-5`)을 쓴다.

**파이프라인 안 AI (`AI_PIPELINE`, 기본 `true`).** 같은 제공자를 검사 자체에도 쓴다. ① *라이브러리 참조*: 개발 검사에서 잠금 파일이 없어 syft가 구성요소를 하나도 못 찾으면 워커가 소스의 import 문(생태계별 60개까지)과 의존성 파일 앞부분(6개, 1,500자까지)만 AI에 보내 저장소 패키지 이름과 버전을 추정하게 하고, 그 답을 검증(생태계·이름·버전 형식, PURL 생성 가능)해 SPDX 2.3으로 만든 뒤 Grype로 대조한다. 결과의 SBOM 생성 도구는 `EOLWatch-AI-Library-Reference`이고 각 구성요소 comment에 신뢰도·근거가 남는다. 버전은 추정값이므로 화면에 `AI 라이브러리 참조 · 버전 추정`으로 표시한다. AI가 없거나 실패하면 예전처럼 `EMPTY_COLLECTION`으로 끝난다. ② *수집 에이전트*: SSH 점검에서 고정 수집이 끝난 뒤 OS·아키텍처·플랫폼·포트·서비스와 읽기 전용 명령 카탈로그(id·목적)를 AI에 보여 주고 이 서버에 맞는 명령 id를 8개까지 고르게 한다. 카탈로그에 있는 id만 실행되며(AI가 명령 문자열을 만들 수 없다) 출력은 4,000자까지 `server_info.ai_collection`에 저장된다. 같은 모양의 서버는 프로세스 안에서 답을 재사용하고, AI가 없으면 OS 규칙으로 기본 명령을 고른다.

**토큰 다이어트.** AI에는 저장된 데이터만, 그것도 압축해서 보낸다. CVE는 라이브러리별로 묶어 최고 심각도·건수·수정 버전·대표 CVE 2개(설명 60자)만 남기고 라이브러리 15개까지, 서버 정보는 포트 15개·서비스 12개·프로세스 5개·디스크 4개까지만 보낸다. 측정값과 발표용 정리는 `docs/TOKEN_DIET.md`. 설치 패키지 목록(수백 개)은 건수만 보낸다. JSON은 공백 없이 보내고, 같은 데이터·모델이면 저장된 답을 재사용한다. 응답에는 보낸 글자 수와 입력·출력 토큰 수가 남는다. 숨은 추론(thinking) 토큰도 출력처럼 과금되므로 기본으로 `OPENAI_REASONING_EFFORT=none`을 보내 끈다(같은 요약이 1,651→260 토큰). 값을 거부하는 모델에는 자동으로 빼고 다시 보낸다. 토큰·소스 코드·비밀번호는 보내지 않으며 결과는 참고용이다.

## 1. 개발 검사 — 소스 ZIP · 의존성 파일 · Git 저장소

| 방식 | 경로 | 권한 | 용도·query |
|---|---|---|---|
| POST | `/api/analyses/assets/{asset_id}/uploads` | ADMIN | 소스 ZIP 또는 의존성 파일 하나(requirements.txt·package-lock.json·pom.xml 등) 업로드와 검사 요청 · multipart `file`, `project_name`. 의존성 파일은 한 항목 ZIP으로 보관 |
| POST | `/api/analyses/assets/{asset_id}/git` | ADMIN | Git 저장소 검사 요청 · JSON `repository_url`(https, 계정 정보 불가), `ref`(선택), `project_name`, `access_token`(선택, 저장하지 않음) → 범위 `source-git:<project_name>` |

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
| POST | `/api/assets` | ADMIN | 서버(대상) 등록. `ssh_auth`가 `password`면 `ssh_password` 필수(암호화 저장, 응답에 없음). 응답의 `has_password`, `ssh_host_key_fingerprint`로 상태 확인 |
| POST(참고) | `/api/assets` | ADMIN | 서버 등록 |
| GET | `/api/assets/{asset_id}` | 로그인 | 서버 상세 |
| PATCH | `/api/assets/{asset_id}` | ADMIN | 서버 수정 |
| DELETE | `/api/assets/{asset_id}` | ADMIN | 서버 삭제 |
| GET | `/api/assets/{asset_id}/timeline` | 로그인 | 검사 작업·SSH 점검·SBOM 저장·CVE 조치 통합 타임라인 |
| GET | `/api/checks` | 로그인 | SSH 점검(서버 정보 수집) 이력 · `asset_id`, `limit`(1~500) |
| POST | `/api/checks/assets/{asset_id}/run` | ADMIN | SSH 점검 실행 · CPU·메모리·디스크·프로세스·설치 패키지·OS·서버 정보 수집 |
| GET | `/api/checks/{job_id}/result` | 로그인 | 점검 결과 · `raw_metrics.server_info`에 호스트·커널·CPU 모델·메모리 총량·디스크 총량·가상화·DMI·클라우드·IP·수신 포트·실행 서비스 |
| POST | `/api/checks/{job_id}/sbom` | ADMIN | 성공한 점검의 패키지 목록에서 자체 SPDX 생성 |
| POST | `/api/analyses/assets/{asset_id}/jobs` | ADMIN | 서버 취약점 검사 요청 · JSON `scan_scope`(`ubuntu-dpkg-installed`, 본문 생략 가능) |

서버 필드는 `asset_tag`, `name`, `asset_type`(`server`, `storage`, `network`, `security`, `vm`, `cloud`, `other`), `ip_address`, `ssh_port`, `ssh_username`, `monitored`다. 응답에는 `sbom_count`, `vulnerability_counts`(심각도별), `vulnerability_count`가 붙는다. 건물·랙·구매가·담당자 같은 재고 필드는 없다.

## 3. 검사 기록

| 방식 | 경로 | 권한 | 용도·query |
|---|---|---|---|
| GET | `/api/analyses` | 로그인 | 최근 검사 결과 100건 |
| GET | `/api/analyses/history` | 로그인 | 모든 성공 검사 페이지 · `asset_id`, `scan_scope`, `q`, `date_from`, `date_to`, `limit`, `offset` |
| GET | `/api/analyses/job-history` | 로그인 | 작업 이력 페이지 · 위 필터와 `status` |
| GET | `/api/analyses/projects` | 로그인 | 서버·범위별 프로젝트 요약 · `asset_id`, `scan_scope`, `q`, 페이지 |
| GET | `/api/analyses/runs/{run_id}` | 로그인 | 원본 JSON을 제외한 검사 메타데이터 |
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
| GET | `/api/sboms/{sbom_id}/components/{component_id}` | 로그인 | 구성요소 상세 |
| GET | `/api/sboms/{sbom_id}/components` | 로그인 | 구성요소 목록 · `q` |
| GET | `/api/vulnerabilities` | 로그인 | 구성요소·CVE·VEX 조회 · `sbom_id`, `vex_status` |
| GET | `/api/vulnerabilities/{link_id}` | 로그인 | 개별 CVE 연결의 현재 조치 상태 |
| PATCH | `/api/vulnerabilities/{link_id}/vex` | ADMIN | 수동 VEX 상태 변경 |
| POST | `/api/vulnerabilities/{link_id}/actions` | ADMIN | 조치 상태·조치 내용 기록 |
| GET | `/api/vulnerabilities/{link_id}/actions` | 로그인 | 조치 이력 · `limit`, `before_id` |
| GET, HEAD | `/api/vulnerability-work` | 로그인 | CVE 목록 서버 페이지 (검사 기록 · CVE 결과·조치 화면이 사용) |
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

## 7. 인프라 검사 요청

```bash
curl --fail-with-body -X POST \
  http://127.0.0.1:18080/api/analyses/assets/1/jobs \
  -H "Authorization: Bearer $EOLWATCH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scan_scope":"ubuntu-dpkg-installed"}'
```

서버 검사 범위는 `ubuntu-dpkg-installed` 하나다(본문 생략 시 기본값). 서버에는 검사 대상 설정(`monitored`)·IP·SSH 계정이 필요하고 키·호스트 키는 관리 서버에 설정한다. 임의 명령·개인키·경로·허용하지 않은 필드는 받지 않는다.

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

## 10. 조치 이력

`GET /api/vulnerabilities/{link_id}`로 현재 `review_revision`을 읽고 다음 요청에 넣는다.

```json
{
  "expected_revision": 0,
  "status": "UNDER_INVESTIGATION",
  "detail": "업데이트 일정을 확인했습니다.",
  "justification": "reviewing",
  "response": "update"
}
```

`POST /api/vulnerabilities/{link_id}/actions`는 로그인한 관리자에서 작성자를 결정한다. 클라이언트가 작성자를 직접 지정할 수 없다. `expected_revision`은 0 이상, `detail`은 공백을 제거한 1~2000자다. `justification`·`response`는 선택이다.

응답은 갱신된 CVE 연결에 `review_revision`을 포함한다. 같은 이전 버전의 요청이 경합하면 한 건만 반영되고 나머지는 **409**다. 현재 상태·전후 스냅샷·작성자·도메인 감사 로그를 한 트랜잭션으로 저장한다. 선택 필드의 생략은 현재 값을 유지하고 명시적 `null`은 값을 지운다. `FIXED`는 메모를 남긴 운영자의 판단이며 재검사 결과로 자동 처리하지 않는다. 재검사 미검출은 [검사 전후 비교](COMPARISON_REPORTS.md)로 따로 확인한다.

`GET /api/vulnerabilities/{link_id}/actions?limit=100&before_id=...`는 최신 ID부터 `items`, `has_more`, `next_before_id`를 반환한다. `limit`은 1~100이다. 작성 당시 사용자 이름과 전후 상태 스냅샷을 보관하며 이후 이름이 달라져도 기존 이력을 다시 계산하지 않는다.

화면·판단 기준·검증 범위는 [조치 이력 안내](VULNERABILITY_ACTIONS.md)를 따른다.

## 11. 수동 VEX

`PATCH /api/vulnerabilities/{link_id}/vex`의 필수 입력은 `status`다. 허용 값은 `AFFECTED`, `NOT_AFFECTED`, `FIXED`, `UNDER_INVESTIGATION`이며 `justification`, `response`, `detail`을 함께 남길 수 있다. 이 경로도 같은 조치 서비스로 상태·이력을 함께 저장한다. `expected_revision`을 제공하면 경합을 검사하고, 생략하면 잠근 최신 버전을 사용한다. 메모 생략은 `legacy_vex`, `note_provided: false`로 이력에 표시하고 기존 현재 메모는 유지한다. 미검출 결과만으로 자동 호출하지 않는다.

CVE 매칭은 Grype 한 곳에서 하며 외부 OSV 조회는 없다. 전체 모델·입력 필드는 [데이터 모델](DATA_MODEL.md)과 실제 OpenAPI를 확인한다.

## 12. CVE 목록 서버 페이지

`GET /api/vulnerability-work`와 HEAD를 지원한다. 기본 대상은 **전체 SBOM 이력의 미완료 조치**다.

| query | 값·기본값 |
|---|---|
| `status` | OPEN(기본), ALL, AFFECTED, UNDER_INVESTIGATION, FIXED, NOT_AFFECTED |
| `q` | CVE·패키지·서버 번호/이름 검색, 최대 200자 |
| `asset_id`, `sbom_id` | 선택 서버·SBOM, 1 이상. 없는 SBOM은 404 |
| `severity` | UNKNOWN, NONE, LOW, MEDIUM, HIGH, CRITICAL |
| `limit`, `offset` | 기본 25/0, limit 1~100, offset 0 이상 |

정렬은 심각도 높은 순 → 연결 ID 순이다.

응답은 `{items,total,limit,offset,as_of,scope}`이며 `scope`는 `ALL_SBOM_HISTORY`다. 각 항목은 기존 CVE 응답과 `asset_id`를 포함한다. 이전 SBOM의 미완료 조치를 새 검사 때문에 숨기지 않는다. count와 페이지를 DB에서 계산하며 원본 SBOM·Grype JSON은 읽지 않는다.

전체 구현과 실제 검증의 구분은 [구현 현황](IMPLEMENTATION_STATUS.md)을 확인한다.
