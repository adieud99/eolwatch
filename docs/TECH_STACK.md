# EOLWatch 기술 스택과 선정 이유

기준일: 2026-09-21. **개발 및 인프라 취약점 검사 솔루션의 현재 코드**를 기준으로 한다. 프로젝트 전체의 개발 완료나 실무 배포 준비 완료를 뜻하지 않는다.

## 1. 현재 사용하는 기술

| 역할 | 실제 기술·버전 | 맡는 일 |
|---|---|---|
| 언어·런타임 | Python 3.12 / Node 22 | API·worker·문서 처리 / 프런트 빌드 |
| API | FastAPI 0.116.1, Uvicorn 0.35.0 | HTTP 요청·응답, OpenAPI |
| 입력 검증 | Pydantic 2.13.5, jsonschema 4.25.1 | 서버·검사 범위·조치 입력과 공식 SBOM 구조 검사 |
| ORM·마이그레이션 | SQLAlchemy 2.0.43, Alembic 1.16.5 | 관계·트랜잭션·DB 변경 이력 |
| DB | PostgreSQL 16 / 테스트용 SQLite | 서버·작업·SBOM·CVE·원본 JSON 보관 |
| 웹 | React 19.3.0, Vite 8.3.0 | 개발 검사·인프라 검사·검사 기록·관리 화면 |
| 수집 | Paramiko 5.0.0, Syft 1.51.1 | 키 기반 SSH 접속, 서버 정보 수집, 설치 구성요소 식별 |
| SBOM | SPDX 2.3 JSON | 검사 경로의 기준 교환 형식. CycloneDX 1.4~1.7 반입 API도 유지 |
| 취약점 대조 | Grype 0.118.0 | SPDX 구성요소와 취약점 DB 대조 |
| 작업 실행 | APScheduler 3.11.0 + DB 작업 큐 | 기본 3초 큐 확인, 일일 SSH 점검 |
| PDF | ReportLab 4.4.4, 번들 Nanum Gothic 글꼴 | 한글 검사 전후 비교 PDF |
| 웹 제공 | Nginx 1.27 계열, Docker Compose | 정적 웹·API 프록시, API·worker·DB 배치 |
| 시연 VM | VirtualBox, Ubuntu 24.04 ARM64 | 노트북 안의 관리 VM 1대와 대상 VM 2대 |
| 테스트 | pytest, FastAPI TestClient, Vitest, Testing Library | 서비스·API·실패 처리·화면 상호작용 검증 |

정확한 운영 Python 패키지는 [requirements.txt](../backend/requirements.txt), 테스트 패키지는 [requirements-dev.txt](../backend/requirements-dev.txt), Node 패키지는 [package.json](../frontend/package.json)과 lockfile을 기준으로 한다. 업로드 파서는 python-multipart 0.0.31이며 Python 3.12 컨테이너에서 검증한다. [의존성 변경 근거](DEPENDENCY_REMEDIATION.md)를 참고한다. DB 원본 컬럼은 SQLAlchemy `JSON`이며 JSONB라고 가정하지 않는다. Docker 기본 이미지는 일부 계열 태그를 사용하므로 모든 이미지가 digest로 고정됐다고 설명하지 않는다.

## 2. 이 구성을 선택한 이유

### 웹과 별도 worker

여러 서버·프로젝트의 검사 결과와 조치 정보를 한곳에서 확인하기 위해 브라우저를 관리 화면으로 사용한다. 검사는 API 요청보다 오래 걸리므로 API가 DB에 작업을 넣고 별도 worker가 처리한다. 화면 이동·새로고침과 검사 실행을 분리하고 진행·실패·재시도·취소 이력을 남길 수 있다.

### 기존 검사 도구와 자체 관리 기능

Syft의 구성요소 식별과 Grype의 취약점 대조를 활용한다. 직접 만든 부분은 서버 등록과 SSH 서버 정보 수집, ZIP 입력 제한, 실행 제어·실패 복구, 원본 검증·저장, CVE 조회·조치 기록, 전후 비교와 보고서다. Black Duck 같은 상용 도구는 요구하지 않는다.

### PostgreSQL과 원본 보관

서버→SBOM→구성요소→CVE 관계에는 FK·고유 제약·트랜잭션을 적용한다. 작업 성공과 검사 결과 저장을 하나의 트랜잭션으로 처리해 부분 저장을 막는다. 조회용 연결 값과 각 검사의 원본 JSON을 함께 보관하므로 수동 VEX 변경 후에도 원본 전후 비교가 가능하다.

### DB 작업 큐와 APScheduler

현재 규모는 관리 VM 한 대와 대상 두 대다. 별도 Redis·Celery를 추가하지 않고 `analysis_jobs`와 worker의 주기 실행을 사용한다. 고유 활성 서버 값, 작업 확보, 소유권 토큰과 heartbeat를 사용한다. 이는 대규모 분산 큐의 성능을 검증했다는 뜻이 아니다. APScheduler가 예약하는 것은 검사 큐 확인과 일일 SSH 점검이다.

### 제한된 SSH 수집 범위

Ubuntu dpkg와 고정 Python 가상환경을 먼저 지원해 수집 범위를 검증할 수 있게 했다. 상주하는 자체 에이전트 대신 요청 때 Syft를 복사해 실행하지만, 대상 사용자 디렉터리에 도구·임시 파일을 배치한다. 실행 도구 체크섬, known_hosts 검증, 시간·출력 크기 제한을 적용한다. 서버 정보 수집 명령은 모두 읽기 전용이며 도구가 없어도 실패하지 않는다. 임의 프로그램 업로드나 임의 경로 실행은 제공하지 않는다.

### ReportLab

저장된 비교 자료를 API에서 PDF로 만든다. 번들 한글 글꼴을 사용하고 원격 URL을 가져오지 않으며 검사 범위·원본 식별·제한 사항을 함께 담는다. 같은 자료의 JSON도 내려받아 구조화된 결과를 확인할 수 있다. 비교·보고서 요청은 VEX를 자동 변경하지 않는다.

## 3. 인증과 운영의 실제 수준

- 비밀번호는 Python 표준 라이브러리의 **PBKDF2-HMAC-SHA256**과 개별 salt를 사용한다.
- 액세스 토큰은 HS256 JWT이며 ADMIN/VIEWER와 활성 계정 여부를 검사한다. 사용자·감사 로그 조회는 ADMIN 전용이다.
- SSH 개인키·known_hosts는 파일 마운트로 전달한다.
- 성공한 로그인·변경 요청을 감사 로그에 남긴다. 변경 전후 전체 데이터가 모두 저장된다고 보장하지 않는다.
- GitHub Actions는 백엔드 검사·마이그레이션, 프런트 검사·빌드, 컨테이너 빌드를 구성한다. 현재 워크플로에는 EC2 자동 배포 단계가 없다.
- 실제 Chrome 조작 검증과 자동 테스트를 함께 사용했다. 저장소에 모든 흐름의 Playwright E2E나 Ruff 검사가 이미 구성됐다고 설명하지 않는다.

실무를 위한 조직별 권한 격리, 로그인 실패 제한, 최소 SSH 권한과 복구 운영은 별도 보완 영역이다. 최신 진행 상태는 [구현 현황](IMPLEMENTATION_STATUS.md)을 따른다.

## 4. 제거한 기능과 과거 선택

2026-09-18 재범위화에서 EOL 일정·공개 EOL 카탈로그(endoflife.date)·고객·계약·소프트웨어 원장·자산 재고·위험 점수·Teams 알림·EOL/점검/자산 PDF·CSV 등록 코드를 제거했다. 관련 라이브러리 의존성은 남아 있을 수 있으나 기능으로 설명하지 않는다. Recharts·WeasyPrint·cyclonedx-python-lib·SSM 수집을 사용 중인 기술로 표시하지 않는다.

AWS Terraform·Caddy·S3 스크립트와 [과거 배포 기록](AWS_DEPLOYMENT_RECORD.md)은 이전 환경 자료다. 현재 실행 상태를 새로 확인한 것이 아니며 로컬 시연에 AWS를 요구하지 않는다.

구조는 [ARCHITECTURE.md](ARCHITECTURE.md), 데이터 관계는 [DATA_MODEL.md](DATA_MODEL.md), API는 [API.md](API.md), 실제 검사 설정은 [WEB_ANALYSIS.md](WEB_ANALYSIS.md)를 참고한다.
