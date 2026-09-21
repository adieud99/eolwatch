# EOLWatch 문서 안내

현재 프로젝트는 **웹에서 소스 ZIP·서버 프로젝트·설치 패키지를 분석하고 자산별 CVE·지원 종료·조치 업무를 관리하는 서비스**다. 로컬 관리 VM 1대와 대상 VM 2대가 시연 기준이며 Black Duck은 필수가 아니다.

## 현재 기준으로 읽을 문서

| 순서 | 문서 | 확인할 내용 |
|---|---|---|
| 1 | [현재 범위](SCOPE_V3.md) | 프로젝트 목적, 전체 구성, 포함·제외 범위와 완료 기준 |
| 2 | [구현 현황](IMPLEMENTATION_STATUS.md) | 완료한 기능, 실제 검증, 남은 작업 |
| 3 | [프로젝트 구성도·단계별 계획](PROJECT_CONFIGURATION_AND_ROADMAP.md) | 전체 구성도, 기능 묶음, 사용자 흐름, 다음 진행 순서 |
| 4 | [웹 분석 실행](WEB_ANALYSIS.md) | 웹 요청·worker·SSH·Syft·SPDX·Grype 구조, API와 운영 설정 |
| 5 | [조치 시연 안내](REMEDIATION_DEMO.md) | 교수님께 보여줄 관리 앱·대상 앱과 업데이트·재분석 순서 |
| 6 | [비교 보고서 안내](COMPARISON_REPORTS.md) | 웹에서 PDF·JSON을 내려받고 전후 결과·분석 근거 제시 |
| 7 | [CVE 조치 관리](VULNERABILITY_ACTIONS.md) | 담당자·기한·조치 내용·재분석 근거와 변경 이력 |
| 8 | [프로젝트 이력·공개 EOL](PROJECT_HISTORY_AND_EOL.md) | 전체 이력·저장 ZIP·취소·공개 지원 일정 비교와 적용 |
| 9 | [프로젝트 확장 검증](PROJECT_EXPANSION_VERIFICATION.md) | 실제 ZIP·서버 경로·예약 분석, 관리 화면, OSV와 백업 복구 |
| 10 | [교수님 설명 안내](PROFESSOR_PROJECT_GUIDE.md) | 전체 구조, 웹 애플리케이션, 화면별 시연 시나리오 |
| 11 | [운영 백업](BACKUP_OPERATIONS.md) | DB·원본 ZIP 백업, 복구 검증과 정기 실행 |
| 12 | [작업 재개](NEXT_SESSION.md) | 접속 주소·직전 반영 내용·검증 배포 명령과 다음 작업 |

실제 이력은 <http://127.0.0.1:18080>의 관리 VM DB에 있다. 맥 Docker의 <http://127.0.0.1:8080>은 별도 개발 DB다. 데모 앱의 미검출 결과를 전체 OS의 취약점 해소나 자동 VEX 조치 완료로 해석하지 않는다.

## 기능별 세부 안내

| 문서 | 확인할 내용 |
|---|---|
| [현재 분석 지표와 보관 이력](CURRENT_INVENTORY.md) | 대시보드의 현재 위험과 누적 이력 구분, `current_inventory` 필드 |
| [분석 취소와 정리 확인](ANALYSIS_CANCELLATION.md) | 취소 요청 상태표, API, 프로세스 종료 확인 |
| [의존성 보완 근거](DEPENDENCY_REMEDIATION.md) | 자체 소스 분석으로 바꾼 직접 의존성과 공식 공지 대조 |
| [도구 연동 안내](ANALYSIS_TOOLS.md) | 수동 OS 분석·결과 반입용 맥 스크립트 경로 |
| [EOL 카탈로그 검증 인계](LIFECYCLE_CATALOG_HANDOFF.md) | 공개 EOL 적용 검증의 중단 지점과 재사용할 검증 데이터 |

## 보관 기록 — `archive/`

`docs/archive/`는 **지난 시점의 사실 기록**이다. 삭제하지 않고 보존하되, 현재 상태를 설명할 때 인용하지 않는다. 최신 구현·검증 범위와 수치는 [프로젝트 확장 검증](PROJECT_EXPANSION_VERIFICATION.md)을 기준으로 한다.

2026-09-15 하루 동안 기능별로 남긴 검증 기록:

| 문서 | 당시 완료한 범위 |
|---|---|
| [기본 상태 검증](archive/VERIFICATION_2026-09-15.md) | 로컬 환경·SSH 수집·자체 SPDX 생성 |
| [도구 연동 검증](archive/ANALYSIS_VERIFICATION_2026-09-15.md) | 초기 스크립트 기반 Syft·Grype 연동과 결과 저장 |
| [웹 분석 검증](archive/WEB_ANALYSIS_VERIFICATION_2026-09-15.md) | 브라우저 요청부터 관리 worker의 OS 분석·저장까지 |
| [조치 전후 검증](archive/REMEDIATION_VERIFICATION_2026-09-15.md) | Jinja2 3.1.4 → 3.1.6, 분석 #3 → #4, 데모 앱 CVE 3건 → 0건 |
| [비교 보고서 검증](archive/COMPARISON_REPORT_VERIFICATION_2026-09-15.md) | 실제 웹의 PDF·JSON 다운로드와 읽기 전용 결과 내보내기 |
| [최신 분석·조치 이력 검증](archive/VULNERABILITY_ACTIONS_VERIFICATION_2026-09-15.md) | 최신 현황, 실제 조치 저장, 충돌 보호, 백업 복원 |

검증 문서의 테스트 개수·DB revision·"다음 단계"는 **해당 검증 시점**을 뜻한다. 이전 조치 관리 시점의 143개·48개와 현재 확장의 394개·120개를 구분한다.

그 밖의 보관 자료:

| 문서 | 보관 이유 |
|---|---|
| [2차 기획](archive/PROJECT_PLAN_V2.md) | 주제 발전 과정. 현재 범위 기준은 [SCOPE_V3](SCOPE_V3.md) |
| [Black Duck 연동 안내](archive/BLACK_DUCK_DEMO.md) | Black Duck을 주 분석 경로로 쓰던 시기의 절차. 현재 시연에 불필요 |

## 제출 자료

| 파일 | 설명 |
|---|---|
| [프로젝트 요약서 PDF](EOLWatch_프로젝트요약서_김연동_수정본.pdf) | **현재 정본.** 원본 소스는 같은 폴더의 `EOLWatch_프로젝트요약서.html`이며, 수정 후 다시 인쇄해 교체한다 |
| [전체 구조·8단계 수행계획 DOCX](EOLWatch_전체구조_8단계_수행계획.docx) | 8단계 수행계획 제출본. 최신 진행 기준은 [PROJECT_CONFIGURATION_AND_ROADMAP.md](PROJECT_CONFIGURATION_AND_ROADMAP.md) |
| [1차 기획안 DOCX](EOLWatch_기획안_김연동.docx), [1차 기획요약 PPTX](EOLWatch_기획요약_김연동.pptx) | 2026-09-01 제출한 1차 자료. 주제 발전 과정 참고용이며 현재 범위 기준이 아니다 |

## 보존한 설계·운영·과거 자료

| 문서 | 현재 읽는 방법 |
|---|---|
| [시스템 아키텍처](ARCHITECTURE.md) | 현재 웹·작업 큐·ZIP·SSH 분석·공유 저장소 구조 |
| [데이터 설계](DATA_MODEL.md) | 자산·SBOM 도메인 참고. 새 분석 작업·비교 구현은 모델·마이그레이션과 함께 확인 |
| [기술 스택](TECH_STACK.md) | 초기 선정 이유 참고. 현재 도구 버전·지원 범위는 WEB_ANALYSIS 우선 |
| [API](API.md) | 현재 등록 API와 페이지 조회·분석·관리 요청 형식 |
| [배포](DEPLOYMENT.md) | 로컬 개발 실행(1절)과 SSH 점검 계정·known_hosts 규칙(5절)은 현재도 유효. 2~4절 AWS 절차는 과거 기록 |
| [운영](OPERATIONS.md) | 매일 확인 항목과 수집 실패 코드표. 백업·복구는 [운영 백업](BACKUP_OPERATIONS.md)이 현재 기준 |
| [AWS 실제 배포 기록](AWS_DEPLOYMENT_RECORD.md) | 과거 생성·배치·검증 기록. 현재 실행 상태를 보증하는 문서는 아님 |
| [로컬 VM 환경](../infrastructure/local-vm/README.md) | VM 주소·생성·배포 참고. 오래된 Black Duck 시연 순서는 REMEDIATION_DEMO로 대체 |

Mermaid 구조도는 GitHub 미리보기에서 확인할 수 있다. 발표 자료는 현재 분석 흐름과 검증된 화면을 기준으로 구성한다.
