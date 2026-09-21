# 웹 분석 실행 검증 기록

검증일: 2026-09-15

## 결과

브라우저에서 LAB-VM-02의 `취약점 분석` 버튼을 눌러 관리 VM worker의 실제 Syft·Grype 분석, DB 저장, 새 SBOM 자동 선택까지 검증했다.

| 항목 | 결과 |
|---|---|
| 대상 | LAB-VM-02 / 10.77.0.22 / Ubuntu 24.04 ARM64 |
| 요청 | 웹 버튼 → POST `/api/analyses/assets/2/jobs` → HTTP 202 |
| 작업 연결 | 작업 #1 → 분석 #2 → SBOM #11 |
| 관측한 상태 | QUEUED → COLLECTING → SCANNING → IMPORTING → SUCCESS |
| 패키지 | 실제 설치 패키지 669개 |
| SBOM 구성요소 | 670개, 자산 루트 1개 포함 |
| Grype 보고 결과 | 고유 CVE 3,216개, 패키지×CVE 연결 12,241건 |
| 시간 | VM 기록 기준 요청~완료 약 63초, 최초 DB 준비 포함 |
| 웹 결과 | SBOM #11 자동 선택, LAB-VM-02 CVE 표시 |
| 브라우저 | 100행 페이지 이동·SBOM 선택 변경 통과, 실행 오류·API 오류 0건 |
| DB | 맥·VM revision `d8a671ec54f2`, 모델 변경 누락 없음 |

위 탐지 건수는 Grype 보고 결과다. 실제 영향, 수정 버전의 적합성, 조치 전후 확인을 완료했다는 의미는 아니다.

## 실행 위치와 증거

- 운영자 PC: 브라우저만 사용했다. 맥의 수동 분석 스크립트를 실행하지 않았다.
- 대상 VM: SSH 키 인증·엄격한 호스트 키 검증 후 Syft로 dpkg 설치 패키지를 수집했다.
- 관리 VM worker: SPDX 2.3 변환과 Grype 취약점 분석을 실행하고 결과를 저장했다.
- worker의 `/var/lib/eolwatch/analysis/job-1-5ad437be-c22b-4f93-bffc-7219b7b03287/`에 실제 명령, 출력, 도구·입력 해시와 원본이 남아 있다.
- 원본 아티팩트와 취약점 DB는 각각 `analysis_artifacts`, `analysis_cache` Docker 볼륨에 보관한다.
- 실행기 manifest의 `ready_for_import`는 도구 실행 완료를 뜻한다. 최종 저장 완료 여부는 DB 작업의 `SUCCESS`와 분석 ID로 확인한다.

이번 실제 분석 요청은 1건이며, 기존 결과에 대한 추가 브라우저 검증은 조회로만 수행했다.

## 자동 검증

- 백엔드 전체 49개 통과: 기존 22개 + 작업 API·worker 16개 + 실행기 11개.
- 프런트엔드 전체 16개 통과 및 프로덕션 빌드 성공.
- 임시 SQLite upgrade → 모델 검사 → downgrade → upgrade 통과.
- 개발·운영 Compose 설정 검사 통과.
- 맥·VM Docker 이미지 빌드와 기동, API·DB 헬스체크 통과.
- 분석 원본을 생성하는 Syft·Grype 프로세스의 종료 코드 모두 0.

검증에는 중복 요청, 권한 제한, 임의 명령·개인키 요청 거부, 실패 재시도 이력, 부분 저장 롤백, 중단 작업 복구, 이전 worker의 상태 변경 차단, 대상 접속 정보 변경, 프로세스 시간 제한, SSH 출력 처리와 호스트 키 검증이 포함된다. 실패·복구 경로는 자동 테스트로 검증했으며 실제 VM에서 장애를 강제로 발생시키지는 않았다.

## 화면 증거

- `reports/web-analysis-assets.png`: 서버 목록의 분석 버튼
- `reports/web-analysis-running.png`: 진행 중 작업
- `reports/web-analysis-jobs.png`: 완료 상태와 연결된 결과
- `reports/web-analysis-results.png`: 자동 선택된 결과와 CVE 목록

## 사용 방법

<http://127.0.0.1:18080>에 관리자로 로그인 → `작업 대상` → 자산의 `취약점 분석`.

과거 결과는 `CVE 조치`에서 작업 #1의 결과 보기 또는 분석 #2의 CVE 보기를 누른다. 맥 Docker도 같은 소스로 갱신했지만 실제 분석 이력은 VM의 별도 DB에 저장돼 있다.

이 검증 시점의 지원 범위는 worker와 같은 CPU 아키텍처의 Ubuntu 설치 OS 패키지였다. 이후 [데모 앱 업데이트 전후 비교](../REMEDIATION_DEMO.md)를 추가했다. 실제 앱 분석의 근거는 [후속 검증 기록](REMEDIATION_VERIFICATION_2026-09-15.md)에 별도로 보관한다.

상세 구조·API·운영 설정: [WEB_ANALYSIS.md](../WEB_ANALYSIS.md).
