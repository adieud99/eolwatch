# EOLWatch

웹에서 **프로젝트 소스 ZIP·서버 앱 폴더·설치 패키지를 분석**하고, SBOM 상세·CVE 조치·지원 종료·계약을 자산별로 관리합니다. 현재 코드와 실제 실행 근거는 [구현 현황](docs/IMPLEMENTATION_STATUS.md)과 [프로젝트 확장 검증](docs/PROJECT_EXPANSION_VERIFICATION.md)을 기준으로 확인합니다.

EOLWatch는 **웹에서 서버의 SBOM·취약점 분석을 실행하고, 영향받는 자산과 업데이트 전후 결과를 확인하는 인프라 유지관리 서비스**입니다. Syft가 설치 구성요소를 식별하고 Grype가 알려진 취약점과 대조합니다. EOLWatch는 자산 연결, 분석 작업, 원본 보관, CVE 조회와 조치 이력을 담당합니다.

Black Duck은 비교·선택적 연동 대상으로 두며, 현재 기능과 시연에는 Black Duck 계정이나 서버가 필요하지 않습니다. 기존 EOL/EOSL·계약·SSH 상태 점검 기능은 자산 관리의 보조 기능으로 유지합니다. 학교 파이널 프로젝트이며 시스원의 공식 제품이나 내부 시스템을 재현한 것은 아닙니다.

## 전체 구조와 분석 범위

```text
운영자 브라우저
  → 관리 VM: React 웹 · FastAPI · PostgreSQL · 분석 worker
  → 소스 ZIP: 관리 worker에서 Syft 실행 / 대상 VM: SSH로 Syft 실행
  → 관리 VM: SPDX 2.3 변환 · Grype 분석 → 자산별 CVE 저장 → 웹 전후 비교
```

관리 VM 1대와 대상 VM 2대로 시연합니다. 도구는 **Syft 1.51.1 / Grype 0.118.0**으로 고정했습니다.

| 웹에서 선택하는 범위 | 실제 분석 대상 |
|---|---|
| 소스 ZIP 업로드 | 잠금 파일·패키지 명세·설치 메타데이터가 포함된 프로젝트, 압축 50 MiB 이하 |
| 서버 프로젝트 폴더 | 등록된 SSH 서버에서 지정한 절대 경로의 프로젝트 |
| 서버 Python 가상환경 | 지정한 절대 경로에 설치된 Python 패키지 메타데이터 |
| Ubuntu 설치 패키지 | 대상 서버의 dpkg 설치 패키지 |
| 데모 앱 · Python | SSH 사용자의 고정 `~/eolwatch-demo/.venv`에 설치된 라이브러리 |

기준 SBOM 형식은 **SPDX 2.3 JSON**입니다. CycloneDX 1.4~1.7 가져오기도 지원합니다. 소스 분석은 포함된 메타데이터를 읽으며 의존성을 설치하거나 업로드한 프로그램을 실행하지 않습니다. 같은 자산·프로젝트 이름의 ZIP 또는 같은 서버 경로는 전후 비교할 수 있습니다. Git URL·컨테이너 이미지 직접 입력은 지원하지 않습니다.

`프로젝트 분석`에서 서버 분석을 예약하고, `SBOM 원장`에서 패키지·라이선스·의존관계·원본을 탐색합니다. `조치 작업목록`은 담당자·기한 초과·상태·심각도·자산별 검색과 CVE 이력을 제공합니다. `작업 대상`에서 자산을 수정하고 `제품·계약`에서 공통 수명주기·영향 자산·유지보수 계약을 관리합니다.

이 저장소를 분석할 소스 ZIP은 다음 명령으로 만들 수 있습니다. 지정된 소스와 패키지 명세만 포함하며 `.env`·SSH 키·DB·의존성 설치 폴더는 포함하지 않습니다.

```bash
python3 scripts/package-project-source.py
```

생성 파일: `reports/eolwatch-project-source.zip`. 운영 백업은 [DB·업로드 ZIP 백업과 복구](docs/BACKUP_OPERATIONS.md)를 참고합니다.

## 프로젝트 이력과 EOL 일정

`프로젝트·분석 이력`에서 과거 분석을 페이지로 찾아 비교하고, 저장된 ZIP을 내려받거나 같은 입력으로 재분석합니다. 실행 중 작업은 프로세스 종료를 확인한 뒤 취소됩니다. `EOL 일정 조회`는 공개 제품·지원 주기를 선택해 현재 날짜와 비교하고 명시적으로 적용하며, 원본·출처·변경 이력을 보존합니다.

자세한 사용법과 API는 [프로젝트 이력·공개 EOL 일정](docs/PROJECT_HISTORY_AND_EOL.md), 취소 시 중단 복구는 [분석 취소 운영](docs/ANALYSIS_CANCELLATION.md)을 참고합니다.

## 현재 확인한 결과

- 실제 프로젝트 ZIP·서버 폴더·Python 경로 분석, 정기 예약, 실패 후 재시도와 관리 화면 검증
- EOLWatch 자체 직접 의존성 보완 후 같은 소스 범위 CVE **9건 → 0건**: 미검출 8건, pytest 운영 의존성 제거 1건 — [분석 #5 → #10 PDF](reports/eolwatch-source-analysis-5-10.pdf)
- Python 3.12 백엔드 **394개**, 프런트엔드 **120개** 테스트 통과 및 DB·원본 ZIP의 실제 백업 복구 확인
- 웹에서 분석 요청 → 대기·수집·분석·저장 → 결과 자동 선택, 실패 이력과 재시도
- 실제 Ubuntu 패키지 669개 수집·분석 및 자산별 CVE 조회
- `LAB-VM-01`의 데모 앱을 Jinja2 **3.1.4 → 3.1.6**으로 업데이트하고 재분석
- 분석 **#3 → #4**, SBOM **#12 → #13**에서 데모 앱 CVE **3건 → 0건** 확인
- 같은 자산·범위의 원본으로 계속 검출·새로 검출·재분석 미검출·구성요소 제거 비교
- 실제 시연 웹에서 분석 #3 → #4의 비교 PDF·JSON 다운로드 확인

**3건 → 0건은 지정한 데모 앱 가상환경의 결과입니다.** 전체 OS의 취약점 해소나 실제 공격 성공·차단을 입증하는 수치는 아닙니다. 비교는 과거 VEX 상태를 바꾸지 않으며 조치 상태는 운영자가 판단해 기록합니다.

## 시연 접속과 개발 실행

| 주소 | 용도 |
|---|---|
| <http://127.0.0.1:18080> | 관리 VM의 실제 시연 서비스 — 위 분석 이력이 저장된 곳 |
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

백엔드는 Python **3.12**를 기준으로 개발·검증합니다. 운영 의존성은 `backend/requirements.txt`, 테스트 의존성은 `backend/requirements-dev.txt`로 분리했습니다. 기존 Python 3.9 가상환경을 덮어쓰지 않고 같은 실행 환경에서 검사하려면 다음을 사용합니다.

```bash
sh scripts/test-backend.sh
npm --prefix frontend test
npm --prefix frontend run build
```

테스트 컨테이너는 소스·테스트 자료만 읽기 전용으로 연결하고 네트워크 없이 실행합니다. 의존성 변경 근거는 [의존성 보완 기록](docs/DEPENDENCY_REMEDIATION.md)에 있습니다.

기본 실습 로그인은 `admin` / `Eolwatch!2026`입니다. 개발용 합성 데이터가 필요한 경우에만 `docker compose exec api python -m app.seed`를 실행합니다. API 시작 시 Alembic 마이그레이션을 적용하며, 분석 실행에는 대상 서버와 SSH 키·known_hosts 설정이 필요합니다. 세부 설정은 [웹 분석 실행 안내](docs/WEB_ANALYSIS.md)를 따릅니다.

## 교수님께 보여줄 순서

[교수님용 전체 구조·화면·시나리오 안내](docs/PROFESSOR_PROJECT_GUIDE.md)에 구조도와 화면별 설명을 정리했습니다.

1. 관리 VM과 대상 VM, Syft·Grype·EOLWatch의 역할을 구조도로 설명합니다.
2. `프로젝트 분석`에서 실제 소스 ZIP을 업로드하거나 서버 폴더를 지정하고, 진행 상태와 자산 연결을 보여줍니다.
3. SBOM 상세의 구성요소·버전·라이선스·의존관계를 열고 CVE·수정 버전·지원 종료 정보를 확인합니다.
4. 대상 앱을 업데이트한 뒤 같은 범위로 재분석합니다.
5. 이전·이후 버전과 세 CVE의 미검출, 보존된 분석 원본을 보여줍니다.
6. `검증 보고서 PDF`와 `검증 데이터 JSON`을 내려받아 분석 범위·버전 변화·비교 근거를 제시합니다.
7. 조치 작업목록의 담당자·기한·이력과 제품 영향 자산·계약·정기 분석 예약을 보여줍니다.

앱 설치·업데이트는 현재 실습 스크립트로 수행합니다. 상세 명령과 화면 순서는 [조치 시연 안내](docs/REMEDIATION_DEMO.md), 실제 근거는 [조치 전후 검증 기록](docs/archive/REMEDIATION_VERIFICATION_2026-09-15.md)에 있습니다.

보고서 사용법은 [비교 보고서 안내](docs/COMPARISON_REPORTS.md), 다운로드 검증은 [비교 보고서 검증 기록](docs/archive/COMPARISON_REPORT_VERIFICATION_2026-09-15.md)을 확인합니다. 로컬 결과 파일은 `reports/eolwatch-analysis-3-4.pdf`와 `reports/eolwatch-analysis-3-4.json`입니다.

## 문서

- [프로젝트 구성도와 단계별 진행 계획](docs/PROJECT_CONFIGURATION_AND_ROADMAP.md)
- [현재 프로젝트 범위](docs/SCOPE_V3.md)
- [현재 구현 현황과 남은 작업](docs/IMPLEMENTATION_STATUS.md)
- [다음 작업 재개](docs/NEXT_SESSION.md)
- [전체 문서 안내](docs/README.md)
- [프로젝트 요약서 PDF](docs/EOLWatch_프로젝트요약서_김연동_수정본.pdf) — 제출 정본

제출 자료와 과거 기획 자료는 모두 `docs/`에 있습니다. [1차 기획안 DOCX](docs/EOLWatch_기획안_김연동.docx)·[1차 기획요약 PPTX](docs/EOLWatch_기획요약_김연동.pptx), [2차 기획](docs/archive/PROJECT_PLAN_V2.md), [AWS 배포 기록](docs/AWS_DEPLOYMENT_RECORD.md)은 이전 기획·실증 이력으로 보존하며 현재 시연 구성을 뜻하지 않습니다. 최신 기준은 위 범위·구현·검증 문서입니다.
