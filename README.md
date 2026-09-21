# EOLWatch — 개발 및 인프라 취약점 검사 솔루션

EOLWatch는 **개발 소스와 운영 서버의 취약점을 검사하고, 결과를 한곳의 기록에서 다시 보는 웹 서비스**다. 사용자는 소스 ZIP을 올리거나 서버의 IP·SSH 계정을 등록해 검사를 시작한다. Syft가 의존성 목록(SBOM)을 만들고 Grype가 취약점 DB와 대조한다. EOLWatch는 서버 등록, 검사 작업, 원본 보관, CVE 조회, 조치 기록, 전후 비교와 보고서를 담당한다.

2026-09-18에 [재시작 계획](docs/RESTART_PLAN.md)에 따라 범위를 다시 정했다. 이전의 EOL 일정·자산 재고·고객·계약·소프트웨어 원장·Teams 알림 기능은 코드와 DB에서 제거했다(마이그레이션 `d2f8c4a71e9b`). 학교 파이널 프로젝트이며 특정 회사의 제품이나 내부 시스템을 재현한 것은 아니다.

## 세 가지 축

| 축 | 사용자가 하는 일 | 솔루션이 하는 일 | 결과 |
|---|---|---|---|
| 개발 검사 | 소스 ZIP을 올리고 검사를 시작한다 | Syft로 의존성 목록을 뽑고(SPDX 2.3) Grype로 취약점 DB와 대조한다. OSV로 교차 검증할 수 있다 | 라이브러리별 CVE, 수정 버전, 심각도 |
| 인프라 검사 | 서버 IP·SSH 포트·SSH 계정을 등록하고 검사를 시작한다 | Syft를 SSH로 서버에 복사해 실행하고 설치 패키지와 서버 정보(CPU·메모리·디스크 사용률, OS)를 수집한다 | 서버 정보, OS 패키지 CVE |
| 검사 기록 | 과거 검사를 찾아본다 | 검사 이력, CVE 결과와 조치, 조치 작업목록, 의존성 목록, 전후 비교와 PDF·JSON 보고서를 보여준다 | 이력, 비교, 보고서, 조치 기록 |

관리자·조회자 권한과 감사 로그가 있다. 정기 검사 예약은 추가 서비스로, 현재 API로 제공한다.

## 전체 구조

```text
사용자 브라우저
  → 관리 VM: React 웹 · FastAPI · PostgreSQL · 검사 worker
  → 개발 검사: 업로드한 ZIP을 관리 worker에서 Syft로 분석
  → 인프라 검사: SSH로 대상 서버에 Syft 복사·실행, 설치 패키지·서버 정보 수집
  → 관리 VM: SPDX 2.3 변환 · Grype 검사 → CVE 저장 → 검사 기록 · 전후 비교 · 보고서
```

관리 VM 1대와 대상 VM 2대로 시연한다. 도구는 **Syft 1.51.1 / Grype 0.118.0**으로 고정했다. 기준 SBOM 형식은 **SPDX 2.3 JSON**이다.

| 검사 범위 | 실제 검사 대상 |
|---|---|
| 개발 검사 · 소스 ZIP | 잠금 파일·패키지 명세·설치 메타데이터가 든 프로젝트, 압축 50 MiB 이하 |
| 인프라 검사 · OS 설치 패키지 | 등록 서버의 dpkg 설치 패키지 |
| 인프라 검사 · 데모 앱 Python | SSH 계정의 고정 `~/eolwatch-demo/.venv` |
| API 전용 · 서버 경로 | 등록 서버의 절대 경로 프로젝트 폴더(`ssh-project-directory`) 또는 Python 가상환경(`ssh-python-environment`) |

ZIP·폴더 검사는 포함된 메타데이터를 읽으며 의존성을 설치하거나 프로그램을 실행하지 않는다. 같은 서버·같은 범위의 검사는 전후 비교할 수 있다. Git 저장소는 https 주소로 얕게 읽기 전용 복제해 검사하고, 의존성 파일 하나만 올려도 검사한다. 컨테이너 이미지 입력은 지원하지 않는다.

## 화면 구성

| 메뉴 | 내용 |
|---|---|
| 개요 | 등록 서버 수, SBOM·구성요소 수, 미조치 CVE(전체 이력·현재 기준), 서버·범위별 최근 검사 |
| 개발 검사 | 소스 ZIP 업로드 → 검사 실행 → 진행 상태 → 결과 보기 |
| 인프라 검사 | 서버 등록·수정, SSH 점검(서버 정보 수집), 취약점 검사, 서버 정보 수집 이력 |
| 검사 기록 | 검사 이력 · CVE 결과·조치 · 조치 작업목록 · 의존성 목록 · 검사 전후 비교 |

계정은 `.env`의 `ADMIN_PASSWORD`로 만들어지는 관리자 계정을 쓰고, 추가 계정은 `POST /api/auth/users`로 만든다. 화면에는 계정 관리 메뉴가 없다.

이 저장소를 검사할 소스 ZIP은 다음 명령으로 만든다. 지정된 소스와 패키지 명세만 포함하며 `.env`·SSH 키·DB·의존성 설치 폴더는 넣지 않는다.

```bash
python3 scripts/package-project-source.py
```

생성 파일: `reports/eolwatch-project-source.zip`. 운영 백업은 [DB·업로드 ZIP 백업과 복구](docs/BACKUP_OPERATIONS.md)를 참고한다.

## 현재 확인한 결과

- 재범위화 후 테스트: 백엔드 **363 passed** (격리 컨테이너), 프런트엔드 **102 passed** (2026-09-21)
- 개발 검사: EOLWatch 자체 소스 ZIP의 직접 의존성 보완 후 같은 범위 CVE **9건 → 0건** (미검출 8건, pytest 운영 의존성 제거 1건) — [검사 #5 → #10 PDF](reports/eolwatch-source-analysis-5-10.pdf)
- 인프라 검사: `LAB-VM-01` 데모 앱의 Jinja2 **3.1.4 → 3.1.6** 업데이트 후 재검사, 검사 **#3 → #4**에서 CVE **3건 → 0건** — [비교 PDF](reports/eolwatch-analysis-3-4.pdf)
- 실제 Ubuntu 설치 패키지 669개 수집·검사, 서버별 CVE 조회
- 웹에서 검사 요청 → 대기·수집·분석·저장 → 결과 자동 선택, 실패 이력·재시도·취소
- DB·원본 ZIP 백업과 임시 DB 복원 검증

검사 수치는 2026-09-15~16 검증 시점의 기록이다. **3건 → 0건은 데모 앱 가상환경, 9건 → 0건은 소스 ZIP 범위의 결과다.** 전체 OS의 취약점 해소나 실제 공격 성공·차단을 뜻하지 않는다. 비교는 과거 조치 상태를 바꾸지 않으며 조치 완료는 운영자가 판단해 기록한다.

## 시연 접속과 개발 실행

| 주소 | 용도 |
|---|---|
| <http://127.0.0.1:18080> | 관리 VM의 실제 시연 서비스 — 위 검사 이력이 저장된 곳 |
| <http://127.0.0.1:8080> | 맥 Docker의 개발 서비스 — 별도 DB |
| <http://127.0.0.1:8000/docs> | 맥 개발 API 문서 |

기존 로컬 VM 상태 확인:

```bash
./infrastructure/local-vm/status.sh
```

맥 개발 서비스를 새로 빌드·실행할 때:

```bash
docker compose up --build -d
```

백엔드는 Python **3.12**를 기준으로 개발·검증한다. 운영 의존성은 `backend/requirements.txt`, 테스트 의존성은 `backend/requirements-dev.txt`로 분리했다. 기존 Python 3.9 가상환경을 덮어쓰지 않고 같은 실행 환경에서 검사하려면 다음을 사용한다.

```bash
sh scripts/test-backend.sh
npm --prefix frontend test
npm --prefix frontend run build
```

테스트 컨테이너는 소스·테스트 자료만 읽기 전용으로 연결하고 네트워크 없이 실행한다. 의존성 변경 근거는 [의존성 보완 기록](docs/DEPENDENCY_REMEDIATION.md)에 있다.

기본 실습 로그인은 `admin` / `Eolwatch!2026`이다. 합성 시연 데이터는 넣지 않는다. 서버는 인프라 검사에서 직접 등록한다. API 시작 시 Alembic 마이그레이션을 적용하며, 인프라 검사에는 대상 서버와 SSH 키·known_hosts 설정이 필요하다. 세부 설정은 [웹 검사 실행 안내](docs/WEB_ANALYSIS.md)를 따르고, 화면에 뜬 오류 문구는 [트러블슈팅](docs/TROUBLESHOOTING.md)에서 찾는다.

## 시연 순서

교수님 발표 순서는 8단계(개요 → 솔루션 전체 구성도 → 시스템 구성도 → 서비스 구성도 → 서비스 설명 → 인프라 설명 → 추가 서비스 → 마무리)이며 발표 자료는 맨 마지막에 만든다. 화면 시연은 다음 순서를 따른다.

1. 개발 검사: 소스 ZIP 업로드 → 진행 상태 → CVE 결과.
2. 인프라 검사: 서버 등록 → SSH 점검(서버 정보) → 취약점 검사 → CVE 결과.
3. 검사 기록: 검사 이력에서 이전·이후 검사를 골라 전후 비교 → PDF·JSON 다운로드 → 조치 기록.
4. 관리: 사용자 권한과 감사 로그. 추가 서비스로 정기 검사 예약을 소개한다.

세부 시나리오는 [교수님용 전체 구조·화면·시나리오 안내](docs/PROFESSOR_PROJECT_GUIDE.md), 데모 앱 업데이트 명령은 [조치 시연 안내](docs/REMEDIATION_DEMO.md), 보고서 사용법은 [비교 보고서 안내](docs/COMPARISON_REPORTS.md)를 따른다.

## 문서

- [재시작 계획 — 기준 문서](docs/RESTART_PLAN.md)
- [현재 프로젝트 범위](docs/SCOPE_V3.md)
- [현재 구현 현황과 남은 작업](docs/IMPLEMENTATION_STATUS.md)
- [프로젝트 구성도와 단계별 진행 계획](docs/PROJECT_CONFIGURATION_AND_ROADMAP.md)
- [다음 작업 재개](docs/NEXT_SESSION.md)
- [전체 문서 안내](docs/README.md)

[2차 기획](docs/archive/PROJECT_PLAN_V2.md)과 [AWS 배포 기록](docs/AWS_DEPLOYMENT_RECORD.md)은 이전 기획·실증 이력으로 보존하며 현재 시연 구성을 뜻하지 않는다. 과거 검증 기록(`docs/archive/`, [프로젝트 확장 검증](docs/PROJECT_EXPANSION_VERIFICATION.md))에는 지금은 제거한 제품·계약·EOL 화면의 검증 내용이 그 시점의 기록으로 남아 있다.
