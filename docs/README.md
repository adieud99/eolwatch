# EOLWatch 문서 안내

현재 프로젝트는 **개발 및 인프라 취약점 검사 솔루션**이다. 소스 ZIP을 올리는 개발 검사, 서버 IP·SSH 계정을 등록하는 인프라 검사, 두 검사의 결과를 다시 보는 검사 기록으로 구성한다. 2026-09-18 [재시작 계획](RESTART_PLAN.md)이 기준 문서이며, 다른 문서가 이 계획과 충돌하면 재시작 계획을 따른다. 로컬 관리 VM 1대와 대상 VM 2대가 시연 기준이다.

## 현재 기준으로 읽을 문서

| 순서 | 문서 | 확인할 내용 |
|---|---|---|
| 1 | [재시작 계획](RESTART_PLAN.md) | 솔루션 정의, 4개 메뉴, 코드 재사용 지도, 인프라 검사 보강 항목, 진행 순서 |
| 2 | [현재 범위](SCOPE_V3.md) | 세 축의 포함·제외 범위와 판단 기준 |
| 3 | [구현 현황](IMPLEMENTATION_STATUS.md) | 완료한 기능, 제거한 기능, 테스트 수, 남은 작업 |
| 4 | [프로젝트 구성도·단계별 계획](PROJECT_CONFIGURATION_AND_ROADMAP.md) | 전체 구성도, 기능 묶음, 사용자 흐름, 다음 진행 순서 |
| 5 | [웹 검사 실행](WEB_ANALYSIS.md) | 개발 검사·인프라 검사·검사 기록 화면 사용법과 운영 설정 |
| 6 | [조치 시연 안내](REMEDIATION_DEMO.md) | 데모 앱 업데이트 전후 재검사 순서 |
| 7 | [비교 보고서 안내](COMPARISON_REPORTS.md) | 검사 전후 비교 PDF·JSON 다운로드와 해시 |
| 8 | [CVE 조치 관리](VULNERABILITY_ACTIONS.md) | 담당자·기한·조치 내용·재검사 근거와 변경 이력 |
| 9 | [검사 이력·저장 ZIP·취소](PROJECT_HISTORY.md) | 전체 이력 검색, 저장 ZIP 재검사, 취소, 현재 기준 집계 |
| 10 | [교수님 설명 안내](PROFESSOR_PROJECT_GUIDE.md) | 전체 구조, 화면별 시연 시나리오, 예상 질문 |
| 11 | [운영 백업](BACKUP_OPERATIONS.md) | DB·원본 ZIP 백업, 복구 검증과 정기 실행 |
| 11a | [재범위화 검증 기록](RESCOPE_VERIFICATION_2026-09-21.md) | 마이그레이션·개발 검사 API 흐름·권한 검증 결과 |
| 12 | [작업 재개](NEXT_SESSION.md) | 접속 주소·직전 반영 내용·검증 배포 명령과 다음 작업 |

실제 이력은 <http://127.0.0.1:18080>의 관리 VM DB에 있다. 맥 Docker의 <http://127.0.0.1:8080>은 별도 개발 DB다. 데모 앱의 미검출 결과를 전체 OS의 취약점 해소나 자동 조치 완료로 해석하지 않는다.

## 기능별 세부 안내

| 문서 | 확인할 내용 |
|---|---|
| [분석 취소와 정리 확인](ANALYSIS_CANCELLATION.md) | 취소 요청 상태표, API, 프로세스 종료 확인 |
| [의존성 보완 근거](DEPENDENCY_REMEDIATION.md) | 자체 소스 검사로 바꾼 직접 의존성과 공식 공지 대조 |
| [도구 연동 안내](ANALYSIS_TOOLS.md) | Syft·Grype 설치, 수동 OS 검사·결과 반입용 맥 스크립트 |

## 설계·운영 문서

| 문서 | 현재 읽는 방법 |
|---|---|
| [시스템 아키텍처](ARCHITECTURE.md) | 웹·작업 큐·ZIP·SSH 검사·서버 정보 수집·저장소 구조 |
| [데이터 설계](DATA_MODEL.md) | 현재 테이블·컬럼과 마이그레이션 순서 (`d2f8c4a71e9b`까지) |
| [기술 스택](TECH_STACK.md) | 사용 기술·버전과 선정 이유 |
| [API](API.md) | 개발 검사 / 인프라 검사 / 검사 기록 / 인증·관리로 나눈 현재 엔드포인트 |
| [배포](DEPLOYMENT.md) | 로컬 개발 실행(1절)과 SSH 점검 계정(5절)은 현재도 유효. 2~4절 AWS 절차는 과거 기록 |
| [운영](OPERATIONS.md) | 매일 확인 항목과 수집 실패 코드표 |
| [로컬 VM 환경](../infrastructure/local-vm/README.md) | VM 주소·생성·배포 참고 |

## 과거 기록

`docs/archive/`와 아래 문서는 **지난 시점의 사실 기록**이다. 삭제하지 않고 보존하되 현재 상태를 설명할 때 인용하지 않는다. 이 기록에는 2026-09-18에 제거한 제품·계약·고객·EOL·자산 재고 화면의 검증 내용이 그 시점 기록으로 남아 있다.

| 문서 | 당시 완료한 범위 |
|---|---|
| [프로젝트 확장 검증](PROJECT_EXPANSION_VERIFICATION.md) | 2026-09-15~16 실제 ZIP·서버 경로·예약 검사, 당시 관리 화면, OSV, 백업 복구 |
| [AWS 실제 배포 기록](AWS_DEPLOYMENT_RECORD.md) | 과거 AWS 생성·배치·검증 기록. 현재 실행 상태를 보증하지 않음 |
| [기본 상태 검증](archive/VERIFICATION_2026-09-15.md) | 로컬 환경·SSH 수집·자체 SPDX 생성 |
| [도구 연동 검증](archive/ANALYSIS_VERIFICATION_2026-09-15.md) | 초기 스크립트 기반 Syft·Grype 연동과 결과 저장 |
| [웹 분석 검증](archive/WEB_ANALYSIS_VERIFICATION_2026-09-15.md) | 브라우저 요청부터 관리 worker의 OS 검사·저장까지 |
| [조치 전후 검증](archive/REMEDIATION_VERIFICATION_2026-09-15.md) | Jinja2 3.1.4 → 3.1.6, 검사 #3 → #4, 데모 앱 CVE 3건 → 0건 |
| [비교 보고서 검증](archive/COMPARISON_REPORT_VERIFICATION_2026-09-15.md) | 실제 웹의 PDF·JSON 다운로드와 읽기 전용 결과 내보내기 |
| [최신 분석·조치 이력 검증](archive/VULNERABILITY_ACTIONS_VERIFICATION_2026-09-15.md) | 실제 조치 저장, 충돌 보호, 백업 복원 |
| [2차 기획](archive/PROJECT_PLAN_V2.md) | 주제 발전 과정. 현재 범위 기준은 [SCOPE_V3](SCOPE_V3.md) |
| [Black Duck 연동 안내](archive/BLACK_DUCK_DEMO.md) | Black Duck을 주 분석 경로로 쓰던 시기의 절차. 현재 시연에 불필요 |

검증 문서의 테스트 개수·DB revision·"다음 단계"는 **해당 검증 시점**을 뜻한다. 현재 수치는 백엔드 348 passed / 2 skipped, 프런트엔드 100 passed(2026-09-21)이며 [구현 현황](IMPLEMENTATION_STATUS.md)을 기준으로 한다.

## 발표 자료

발표 자료는 교수님 8단계 순서(개요 → 솔루션 전체 구성도 → 시스템 구성도 → 서비스 구성도 → 서비스 설명 → 인프라 설명 → 추가 서비스 → 마무리)로 맨 마지막에 만든다. `presentation_design/`에는 이전 요약서 디자인 작업물이 있으며 새 프레임에 맞춰 다시 쓴다. Mermaid 구조도는 GitHub 미리보기에서 확인할 수 있다.
