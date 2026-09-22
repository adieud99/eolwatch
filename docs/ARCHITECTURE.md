# EOLWatch 전체 구조

코드 기준: 2026-09-22. 이 문서는 구현된 구조를 코드 그대로 적는다. 실행 결과·검증 수치는 [구현 현황](IMPLEMENTATION_STATUS.md), [커널 CVE 검증](KERNEL_CVE_VERIFICATION_2026-09-22.md), [실사용 가이드](PRACTICAL_USE.md)에 있다.

## 1. 구성과 데이터 흐름

```mermaid
flowchart LR
    Browser[사용자 브라우저]
    subgraph Controller[관리 서버 · Docker Compose 4개 컨테이너]
        Web[web · nginx + React 정적 파일]
        API[api · FastAPI]
        DB[(db · PostgreSQL 16)]
        Worker[worker · APScheduler + Syft/Grype]
        Upload[(analysis_uploads · ZIP 원본)]
        Artifacts[(analysis_artifacts · 작업 산출물)]
        Cache[(analysis_cache · Grype 취약점 DB)]
        Secrets[(secrets · SSH 키·known_hosts, 읽기 전용)]
    end
    Target[대상 서버 · Ubuntu/Debian · SSH]
    Feed[grype.anchore.io · 일일 DB 빌드]
    AI[AI 제공자 · OpenAI 호환 / Anthropic]
    Browser -->|:8080| Web -->|/api/| API
    API --> DB
    API -->|ZIP 저장| Upload
    API -->|SSH 점검 · 읽기 전용 명령| Target
    Worker -->|3초마다 대기 작업 확보| DB
    Worker -->|SFTP로 Syft 복사 · syft scan| Target
    Upload -->|해시 검증 · 제한된 해제| Worker
    Feed --> Cache --> Worker
    Worker -->|SPDX·Grype JSON·CVE 저장| DB
    Worker --> Artifacts
    API -->|요약 · 선별 · 조치 가이드 (식별자 제거)| AI
    Worker -->|라이브러리 참조 · 수집 에이전트| AI
    Secrets --> API
    Secrets --> Worker
```

- 브라우저는 web(nginx)에만 접속한다. nginx가 `/api/`를 api로 넘기고 요청마다 컨테이너 주소를 다시 찾는다(`frontend/nginx.conf`, resolver 127.0.0.11).
- api는 요청을 처리하고 DB에 쓴다. 검사 요청은 `analysis_jobs` 행으로만 남긴다. SSH 점검(서버 정보 수집)만 api가 동기로 실행한다.
- worker는 3초마다 `SELECT ... FOR UPDATE SKIP LOCKED`로 작업 한 건을 잡아 SSH 수집 또는 ZIP 해제 → SPDX 변환 → Grype 대조 → 저장을 한 트랜잭션으로 끝낸다. 매일 08:30에 등록 서버의 SSH 점검도 돈다(`app/worker.py`).
- 대상 서버에는 상주 프로세스가 없다. 요청 때 검증된 Syft 바이너리 한 개를 SFTP로 복사해 실행하고, 서버 정보는 읽기 전용 명령으로 받는다.
- AI는 선택 기능이며 api·worker가 HTTPS로 제공자를 부른다. 보내는 데이터는 [AI 정책](AI.md)대로 식별자를 뺀 압축본이다.

## 2. 두 축의 입력과 검사 범위

| 축 | 프로필 | 수집 위치 | 저장되는 `scan_scope` |
|---|---|---|---|
| 개발 검사 | `source-zip` (ZIP·의존성 파일 하나) / `source-git` (https 얕은 복제) | worker 안의 작업별 디렉터리 | `source-zip:<프로젝트>` / `source-git:<프로젝트>` |
| 인프라 검사 | `ubuntu-dpkg-installed` (이름은 유지, 내용은 OS 패키지 전체) | 대상 서버. `/etc/os-release`로 패키지 계열을 정해 `dpkg-db-cataloger` / `rpm-db-cataloger` / `apk-db-cataloger` 중 하나 | 프로필명 |

인프라 검사는 dpkg(Ubuntu·Debian·Mint 등), rpm(RHEL·CentOS·Rocky·Alma·Oracle·Fedora·Amazon Linux·SLES·openSUSE·Photon·Azure Linux), apk(Alpine·Wolfi) 계열을 지원한다(`analysis_executor.OS_FAMILIES`). Grype에는 배포판별 이름·버전 규칙(`GRYPE_DISTROS`: 예 `redhat:9`, `amazonlinux:2023`, `alpine:3.19`)으로 `--distro`를 넘기고, 계열에 맞는 PURL(`pkg:deb/`·`pkg:rpm/`·`pkg:apk/`)이 90% 미만이면 결과를 저장하지 않는다. apt·dnf/yum·zypper·apk 저장소 대조를 모두 지원한다(`package_updates.py`). 배포판 추적기 2차 검증은 현재 Ubuntu만이다. 대상 CPU는 x86_64·arm64 어느 쪽이든 되며 worker가 맞는 Syft를 고른다. ZIP·Git은 빌드·설치·실행 없이 잠금 파일·명세·설치 메타데이터만 읽고, 500 MiB·2 GiB 해제·256 MiB 파일·200,000항목·압축률 100배 한도와 경로·링크·암호화 검사를 거친다(`analysis_uploads.py`).

## 3. SSH 접속과 수집

| 방식 | 자격 증명 보관 | 호스트 키 |
|---|---|---|
| 관리 서버 키 | `secrets/eolwatch_ssh_key` 파일(읽기 전용 마운트) | `secrets/known_hosts` 엄격 검증 |
| 비밀번호 | DB에 Fernet 암호문(`CREDENTIAL_KEY` 또는 `JWT_SECRET` 파생) | 첫 접속 때 기억, 이후 다르면 거부 |
| 개인키 첨부 | DB에 Fernet 암호문 | 같음 |

SSH 점검 명령은 `collector.py`에 문자열로 박혀 있고 스크립트 파일을 올리지 않는다. 자원(`/proc`, `df`, `ps`), 설치 패키지(`dpkg-query`/`rpm`/`apk`), 서버 정보(`hostname`, `uname`, `/proc/cpuinfo`, `systemd-detect-virt`, DMI, EC2 메타데이터, `ip`/`hostname -I`, `ss`/`netstat`, `systemctl`/`rc-status`/`service`)이며, 도구가 없는 배포판을 위한 대체 명령이 붙어 있다. 그 뒤 수집 에이전트가 카탈로그(`ai_collection.py`, 22개 읽기 전용 명령)에서 OS에 맞는 것을 고른다. 결과는 `collection_jobs`·`check_results`에 저장된다.

취약점 검사는 `uname -sm` → Syft 복사(`~/.local/eolwatch-tools/syft-<해시>`, 체크섬 재검증) → `syft scan dir:/`(300초 제한, 프로세스 그룹·pid 파일) → `/etc/os-release` → `apt list --upgradable` 순이다. 비밀값은 어떤 명령 인자·로그·산출물에도 들어가지 않는다. 자세한 목록은 [기술 질문 정리](../../EOLWatch_기술질문_정리.md) 7절과 같다.

## 4. DB 큐와 작업 상태

```text
QUEUED → COLLECTING → SCANNING → IMPORTING → SUCCESS
                 └─ 오류 → FAILED(error_code)      QUEUED ─ 취소 → CANCELLED
실행 중 ─ 취소 → CANCEL_REQUESTED ─ 프로세스 정리 확인 → CANCELLED
```

- 서버당 활성 작업 1건(`active_asset_id` 유니크). 같은 범위·같은 업로드 해시 요청은 기존 작업을 돌려주고, 다른 범위는 409다.
- `worker_token`으로 소유권을 고정하고 5초마다 heartbeat를 갱신한다. 180초 넘게 끊기면 `WORKER_INTERRUPTED`로 정리한다.
- 취소는 로컬 프로세스 그룹과 원격 pid 파일의 프로세스 그룹을 죽이고 정리 증거(manifest `cleanup_confirmed`)를 확인한 뒤 확정한다([취소 운영](ANALYSIS_CANCELLATION.md)).
- Redis·Celery 없이 PostgreSQL 행 잠금만 쓴다. 관리 서버 1대·worker 1개 규모에 맞춘 선택이다.

## 5. CVE 판정과 우선순위

1. **Grype 대조**: SPDX 2.3을 `sbom:` 입력으로, `--distro`와 `using-cpes: false`로 배포판 수정 버전 기준만 쓴다(백포트 오탐 방지). `--by-cve`로 CVE 번호 기준 결과. 이어서 **Trivy 0.74.0**이 같은 SPDX 파일을 검사한다(`trivy sbom … --scanners vuln`). Trivy 결과는 CVE 연결에 `secondary_status`(AGREED / GRYPE_ONLY)로, 검사에는 "두 도구 일치 n · Grype만 n · Trivy만 n"으로 남고 판정 자체는 Grype 것을 쓴다. Trivy가 없거나 실패해도 검사는 성공한다.
2. **반입**(`services/analysis.py`): 구성요소×CVE 연결을 만들고 CVE 번호 기준 `cve_count`를 센다. Grype가 준 **EPSS·CISA KEV·risk**를 연결마다 저장한다(2026-09-22).
3. **apt 대조**(`package_updates.py`): 서버 저장소가 실제로 올릴 수 있는 버전과 수정판을 dpkg 규칙으로 비교해 `UPDATE_AVAILABLE / UPDATE_BELOW_FIX / NO_UPDATE_FOUND`를 남긴다.
4. **분리 집계**(`cve_breakdown.py`): 수정판 있음, 커널(linux 소스), 저장소 확인, 오탐 의심, **KEV, EPSS 1% 이상**을 검사마다 고정 저장한다.
5. **화면**: 결과 표 첫 줄에 "CVE 전체 / 지금 고칠 수 있는 CVE(커널 제외) / 실제 악용 확인 n / 악용 확률 1% 이상 n". CVE별 보기는 같은 CVE가 형제 패키지에 붙은 것을 한 줄로 접고 KEV → 심각도 → EPSS 순으로 정렬한다.
6. **2차 검증**(`verification.py`, 검사 직후 worker가 자동 실행): Ubuntu 보안 추적기로 CVE마다 `released/pending/needed/…` 상태와 버전을, 커널 CNA(kernel.org)로 커널 CVE의 영향 소스 파일을 받아 서버의 `lsmod`·파일시스템·아키텍처와 대조한다. 결과는 연결마다 `tracker_status`·`host_relevance`로, 검사마다 집계로 저장되고 캐시된다.
7. **AI 선별·AI 2차 검토**(`ai_triage.py`): 후보 40건과 서버 사실(+위 근거)을 보내 `해당 / 확인 필요 / 해당 없음 가능성`과 조치를 받고, CVE 하나는 `유효 / 오탐 가능성 / 해당 없음 가능성 / 확인 필요`로 검토받는다. 조치 상태는 바꾸지 않는다.

숫자가 큰 이유와 검증 결과는 [커널 CVE 검증](KERNEL_CVE_VERIFICATION_2026-09-22.md)에 있다. CVSS를 따로 계산하지 않으며 심각도는 Grype 값을 쓴다.

## 6. 조치·비교·보고서

- 조치는 `component_vulnerabilities.vex_status`와 append-only `vulnerability_actions`. `review_revision` 낙관적 잠금으로 동시 수정을 막고 감사 로그를 같은 트랜잭션에 남긴다.
- 전후 비교는 저장된 두 검사의 원본(SPDX+Grype JSON)만 읽어 계속 검출·새로 검출·재검사 미검출·구성요소 제거를 계산한다. 도구·DB가 다르면 경고한다.
- PDF는 ReportLab + 번들 Nanum Gothic, JSON에는 원본 해시가 들어간다.

## 7. 데이터와 저장소

| 테이블 | 목적 |
|---|---|
| assets | 등록 서버·대상. SSH 접속 정보(암호문), 호스트 키 |
| collection_jobs · check_results | SSH 점검 이력, 자원·패키지·서버 정보·수집 에이전트 결과 |
| analysis_uploads | ZIP 원본 sha256·프로젝트·크기 |
| analysis_jobs | 검사 요청·스냅샷·진행·실패·취소·재시도 |
| sbom_documents · components · dependency_edges | SPDX 원본과 검색용 구성요소·의존관계 |
| analysis_runs | Grype 원본, 도구·DB 정보, 해시, 분리 집계 |
| vulnerabilities · component_vulnerabilities | CVE와 구성요소 연결, 심각도·수정판·apt 대조·EPSS·KEV·risk·조치 상태 |
| vulnerability_actions | 조치 이력(전후 스냅샷) |
| ai_summaries | AI 요약·선별·조치 가이드(종류·대상·모델·토큰·프롬프트 해시) |
| users · audit_logs | 계정, 감사 로그 |

| 볼륨 | 내용 |
|---|---|
| postgres_data | DB |
| analysis_uploads | ZIP 원본(api 쓰기, worker 읽기) |
| analysis_artifacts | 작업별 manifest·로그·SBOM·Grype JSON |
| analysis_cache | Grype DB(자동 갱신) |

백업은 `scripts/backup-runtime.py`가 DB 덤프와 참조 ZIP을 묶고 임시 DB 복원으로 검증한다([운영 백업](BACKUP_OPERATIONS.md)).

## 8. 인증·비밀값·경계

- 로그인은 PBKDF2-HMAC-SHA256, 토큰은 HS256 JWT 8시간. 미들웨어가 모든 `/api/`에서 토큰·활성 계정을 검사하고 GET이 아닌 요청은 ADMIN만 통과시킨 뒤 감사 로그에 남긴다.
- `JWT_SECRET`·`ADMIN_PASSWORD`에 기본값이 없고 `.env` 또는 `*_FILE`(Docker secrets)로 준다([비밀값 관리](SECRETS.md)).
- 시연 compose는 web 8080과 api 8000을 연다. DB 포트는 열지 않는다. `docker-compose.prod.yml`은 Caddy 80·443만 연다(현재 시연 구성 아님).
- 범위 밖: 컨테이너 이미지 입력, 자동 패치, 조직별 분리(멀티 테넌트), 클라우드 계정 API 연동. 도구·데이터 라이선스와 타깃층은 [라이선스와 타깃](LICENSES_AND_TARGET.md), 스캐너 대안·버전은 [스캐너 선택](SCANNER_OPTIONS.md).

[API 안내](API.md) · [웹 사용 안내](WEB_ANALYSIS.md) · [교수님용 설명](PROFESSOR_PROJECT_GUIDE.md) · [요약서](PROJECT_SUMMARY.md)
