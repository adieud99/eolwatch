# EOLWatch 재시작 계획: 개발 및 인프라 취약점 검사 솔루션

기준일: 2026-09-18. 교수님이 잡아준 방향을 기준으로 솔루션을 다시 정의한다. 이전의 EOL 일정·자산 재고·계약 관리 중심 프레임과 4장 제안 요약서 작업은 버린다. **코드는 버리지 않고 이 프레임에 맞게 재배치한다.** 이전 계획 문서(구성도·로드맵, 구현 현황 등)는 이 문서와 충돌하면 이 문서를 따른다.

## 1. 솔루션 정의

**개발 및 인프라 취약점 검사 솔루션.** 사용자는 두 가지 방법으로 검사를 시작하고, 결과는 한 곳의 기록에서 다시 본다.

| 축 | 사용자가 하는 일 | 솔루션이 하는 일 | 결과 |
|---|---|---|---|
| 개발 검사 | 소스 ZIP을 업로드하고 검사 버튼을 누른다 | 의존성 목록을 뽑고(Syft → SPDX), 취약점 DB와 대조한다(Grype, OSV 검증) | 라이브러리별 CVE, 수정 버전, 심각도 |
| 인프라 검사 | 서버 IP와 SSH 계정을 등록하고 검사 버튼을 누른다 | 검사 도구를 그 서버에 복사해 실행하고, 하드웨어·OS·클라우드·통신 정보와 설치 패키지를 수집한다 | 서버 정보 카드, OS 패키지 CVE |
| 검사 기록 | 과거 검사를 찾아본다 | DB에 저장된 검사·결과·조치 이력을 보여준다 | 이력 목록, 전후 비교, PDF·JSON 보고서, 조치 기록 |

SBOM은 인프라·개발 양쪽 검사의 중간 산출물이다. 화면에서는 "의존성 목록"으로 부르고, 별도 원장 메뉴로 내세우지 않는다.

## 2. 화면 구성 (새 메뉴)

현재 11개 메뉴를 4개로 줄인다. 코드는 숨기거나 옮기고, 삭제는 나중에 한다.

| 새 메뉴 | 내용 | 가져오는 기존 화면 |
|---|---|---|
| 개요 | 등록 서버 수, 최근 검사, 미조치 CVE 요약 | 운영 개요(`OverviewPanel`)를 축소 |
| 개발 검사 | ZIP 업로드 → 검사 실행 → 진행 상태 → 결과 | 프로젝트 분석(`AnalysisTargets`)의 ZIP 부분, 서버 분석 작업 표 |
| 인프라 검사 | 서버 등록(이름·IP·SSH 계정·포트) → 정보 수집·검사 실행 → 서버 정보 카드 → 결과 | 작업 대상(자산 표)의 SSH 점검·취약점 분석, `AssetEditor`의 접속 정보 부분 |
| 검사 기록 | 검사 이력 검색, CVE 결과, 전후 비교, 보고서 다운로드, 조치 기록 | 프로젝트·분석 이력(`ProjectHub`), CVE 조치, 조치 작업목록, 비교 화면 |

숨기는 메뉴: 고객·사이트, EOL 일정 조회, 제품·계약, 소프트웨어 원장, SBOM 원장. 라우터와 테스트는 그대로 두고 화면 진입만 없앤다. 자산 재고 필드(건물·랙·구매가·전력 등)는 서버 등록 폼에서 뺀다.

## 3. 코드 재사용 지도

### 그대로 쓴다

| 모듈 | 역할 |
|---|---|
| `services/analysis_executor.py` | Syft 서버 복사·실행, SPDX 변환, Grype 스캔. 두 축의 핵심 엔진 |
| `services/analysis_uploads.py` | ZIP 검사·보관·SHA-256 |
| `services/analysis_jobs.py`, `worker.py`, `routers/analysis_controls.py` | 작업 큐, 취소, 재시도 |
| `services/analysis_profiles.py` | 검사 범위 정의 (`source-zip`, `ubuntu-dpkg-installed`, `ssh-project-directory` 등) |
| `services/sbom.py`, `services/vulnerabilities.py`, `services/osv_matching.py` | 결과 저장, CVE 정규화, OSV 교차 검증 |
| `services/analysis_comparison.py`, `comparison_reports.py`, `comparison_report_pdf.py` | 전후 비교, PDF·JSON |
| `routers/analysis_history.py`, `routers/analyses.py`, `routers/sboms.py` | 이력 조회, 결과 조회 |
| `services/vulnerability_actions.py`, `routers/vulnerability_work.py` | 조치 기록·작업목록 |
| `services/collector.py`, `routers/checks.py` | SSH 정보 수집(현재 CPU·메모리·디스크·프로세스·패키지·OS) |
| `services/auth.py`, `routers/auth.py`, 감사 로그 | 로그인, 관리자/조회자 |
| `services/analysis_schedules.py` | 정기 검사. 추가 서비스로 소개 가능 |

### 이름·화면만 바꾼다

| 기존 | 새 의미 |
|---|---|
| `Asset` 모델·`routers/assets.py` | "등록 서버". API는 그대로, 폼은 접속 정보만 노출 |
| `AnalysisTargets.jsx` | 개발 검사 화면의 ZIP 업로드 부분 |
| `ProjectHub.jsx` | 검사 기록 화면 |
| `VulnerabilityActions.jsx`, `VulnerabilityWorklist.jsx` | 검사 기록 안의 조치 탭 |
| `SbomExplorer.jsx` | 결과 상세의 "의존성 목록" 보기 |

### 보류 (코드 유지, 화면에서 숨김)

`lifecycle_catalog`, `component_lifecycle`, `lifecycle_overview`, `products`, `contracts`, `organization`, `software`, `AssetRiskSnapshot`·`risk.py`, `notifications`, `reports.py`(EOL PDF), `LifecycleCatalog.jsx`, `ManagementWorkspace.jsx`.

## 4. 인프라 검사 보강 (유일한 신규 개발)

교수님 메모의 "하드웨어 정보, 운영체제 정보, 클라우드 리소스 정보, IP를 통한 통신 정보"를 `collector.py`에 명령을 추가해 채운다. 저장은 `CheckResult.raw_metrics`(JSON)에 넣어 마이그레이션 없이 시작한다.

| 항목 | 명령 | 비고 |
|---|---|---|
| 호스트·커널 | `hostname`, `uname -r` | |
| CPU 모델·코어 수 | `lscpu` 또는 `/proc/cpuinfo` | |
| 메모리 총량 | `/proc/meminfo` MemTotal | 현재는 사용률만 있음 |
| 디스크 총량·사용량 | `df -P` 전체 열 | 현재는 사용률만 있음 |
| 가상화·클라우드 | `/sys/class/dmi/id/sys_vendor`, `product_name`, `systemd-detect-virt` | Amazon EC2·KVM·VMware·물리 구분 |
| 클라우드 인스턴스 | EC2 IMDSv2 메타데이터(인스턴스 ID·타입·리전) | 2초 타임아웃, 없으면 생략 |
| 통신 정보 | `ip -4 addr`, `ss -tlnp` | IP·수신 포트·서비스 이름 |
| 실행 서비스 | `systemctl list-units --type=service --state=running` | |

화면은 인프라 검사 결과 상단에 "서버 정보 카드"로 보여준다. 이 정보를 취약점 판정에 쓰지는 않는다(설명만 한다).

## 5. 진행 순서

0. **현재 작업 트리 커밋.** 완료 (`5a52a28`).
1. 메뉴 재구성. 완료: 개요·개발 검사·인프라 검사·검사 기록·관리 5개 메뉴 (`73c10b5`). 숨길 메뉴 제거, 개발 검사·인프라 검사 화면 분리, 검사 기록으로 이력·조치·비교 통합. 기존 테스트가 깨지는 부분만 맞춘다.
2. 인프라 검사 보강(4절). 완료: `collector.py` 명령 추가, 파서, 서버 정보 열·카드, 테스트 (`d0592ac`).
3. 두 축을 각각 끝까지 시연 검증. 개발: ZIP 업로드 → 결과 → 기록. 인프라: 서버 등록 → 수집·검사 → 서버 정보 카드 → 결과 → 기록. 이전에 남아 있던 브라우저 검증(ZIP 재분석·취소·과거 비교)도 여기서 같이 끝낸다.
4. 문서 정리. 완료 (2026-09-21). 구현 현황·API·구조 문서를 새 프레임으로 고치고, EOL·계약 관련 서술은 보류 항목으로 옮긴다.
5. 추가 서비스: 정기 검사 예약(구현됨), 결과 요약·조치 가이드의 AI 생성(2026-09-21 구현, `docs/API.md` 0절), PWA로 휴대폰 화면 대응(선택).
6. **발표 자료는 맨 마지막.** 교수님 8단계 순서(개요 → 솔루션 전체 구성도 → 시스템 구성도 → 서비스 구성도 → 서비스 설명 → 인프라 설명 → 추가 서비스 → 마무리)로 작성한다.

## 6. 범위 밖

컨테이너 이미지 검사, 자동 패치, 다중 고객 SaaS 격리, 실제 공격 가능성 판정은 하지 않는다. 클라우드 리소스 정보는 검사 대상 서버 안에서 읽을 수 있는 범위(메타데이터·DMI)로 한정하고, 클라우드 계정 API는 연동하지 않는다.
