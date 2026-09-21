# 프로젝트 입력·관리 업무 확장 검증

검증일: 2026-09-15~16 KST. 환경: 기존 관리 VM의 <http://127.0.0.1:18080>, 대상 서버 LAB-VM-01·02. 실제 Chrome으로 웹 요청을 만들고 관리 worker의 Syft 1.51.1·Grype 0.118.0 실행을 확인했다. Mac 개발 서비스 <http://127.0.0.1:8080>은 별도 DB다.

## 이번에 구현한 기능

- 소스 ZIP 업로드와 자산·프로젝트 이름 연결. 원본 SHA256 저장, API·worker 공유 볼륨, 크기 제한과 안전한 압축 해제.
- 임의의 서버 프로젝트 절대 경로와 Python 가상환경 분석. 자산·경로별 분석 범위를 구분해 전후 비교.
- DB에 저장되는 정기 분석 예약, 중복 작업 방지, 실패 이력과 재시도.
- SBOM 패키지 검색·페이지 조회, 라이선스·식별자·해시·의존관계·원본 다운로드. 동일 패키지의 여러 버전을 보존하는 SBOM 비교.
- 자산 편집, 제품 공통 수명주기와 영향 자산, 계약 등록·수정. 개별 구성요소 날짜 우선 적용 및 제품 날짜 상속.
- CVE 담당자·상태·심각도·미지정·기한 초과 작업목록과 이력. 전체 CVE를 내려받지 않는 서버 페이지 조회.
- OSV 패키지·버전·영향 범위에 맞춘 수정 버전 계산, CVSS 점수 계산, 페이지 누락·부분 실패 처리와 기존 분석·수동 조치 보존.
- DB와 원본 ZIP 백업, 임시 DB 복원·내용 해시 대조, 보관 개수 관리와 정기 실행.
- 고객사·사이트·자산·소프트웨어·사용자 등록 후 폼 초기화와 목록 갱신 오류 수정.
- 서버 시간대와 무관하게 설정한 업무 시간대(기본 Asia/Seoul)로 EOL·기한 초과·목록 기준일을 계산. 자정 경계 검사 포함.

## 배포와 자동 검사

- 최종 Python **3.12.14**·pytest **9.0.3** 격리 컨테이너에서 백엔드 전체 **313개 통과**(37.20초). `pip check` 정상. 최초 확장 검사 283개와 백업 22개에 업무 날짜 검사 8개를 추가했다. Starlette의 폐기 예정 별칭 경고 1건은 실패가 아니다.
- 프런트엔드 전체 **87개** 통과. 실제 비동기 등록 응답 후 목록 갱신 테스트 5개 포함.
- 프런트엔드 빌드 성공. 배포 JS: `index-BdaAfKFv.js`.
- 실습 PostgreSQL의 Alembic revision: `f8b319ac6402` (head). `alembic check`: 추가 변경 없음.
- Mac API 8000·웹 8080·실습 웹 18080 `/health`: HTTP 200.
- 배포 전에 두 DB를 각각 보존 백업했다. 기존 `.env`, SSH 키·known_hosts와 DB 볼륨을 유지했다.

## 실제 프로젝트 분석과 예약

입력은 EOLWatch 자체의 소스·패키지 명세 63개 파일이다. `.env`, SSH 키, DB, 설치된 의존성 폴더는 포함하지 않았다. 최초 ZIP은 `reports/eolwatch-project-source-before-updates.zip`, 174,423바이트, SHA256 `2fd76afe266598104318e0ef61157394c311ffe1c832ea141ea82a0fc60f4ab8`이다.

| 입력 | 작업 → 분석 → SBOM | 결과 |
|---|---|---|
| 웹 소스 ZIP, LAB-VM-01 | #4 → #5 → #14 | 구성요소 23개, CVE 9개·연결 9건 |
| 서버 프로젝트 경로, LAB-VM-01 | #5 → #6 → #15 | 구성요소 23개, CVE 9개·연결 9건 |
| 같은 경로, LAB-VM-02 정기 예약 | #6 → #7 → #17 | 구성요소 23개, CVE 9개·연결 9건 |
| 지정 Python 가상환경, LAB-VM-01 | #7 → #8 → #18 | Jinja2 3.1.6 확인, 구성요소 3개, CVE 0개 |

서버 프로젝트 경로는 `/home/eolwatch/eolwatch-projects/source-20260915T144331Z`다. Python 경로는 `/home/eolwatch/eolwatch-demo/.venv`다.

예약 #1은 실제 5분 주기로 등록했다. 최초 예정 시각 `2026-09-15T14:49:50.142595Z` 이후 `14:49:50.897609Z`에 worker가 작업 #6을 생성했다. 완료 후 웹에서 일시 중지했다. DB의 예정 시각이나 시스템 시계를 변경해 실행을 앞당기지 않았다.

소스 ZIP 분석은 **포함된 명세·메타데이터에서 도구가 식별한 구성요소**의 결과다. 패키지를 설치하거나 프로그램을 실행하지 않으므로 메타데이터에 없는 의존성과 실제 실행 경로까지 모두 검증한 것은 아니다. 위 9건은 조치 전 소스 스냅샷의 탐지 결과다.

근거: [프로젝트 분석 기록](../reports/project-analysis-verification.json), [ZIP 입력 화면](../reports/project-upload.png), [예약 완료 화면](../reports/project-schedule-completed.png).

## EOLWatch 자체 의존성 수정과 전후 비교

위 최초 분석에서 발견한 직접 의존성의 CVE를 공식 공지와 대조했다. 운영 API의 python-multipart를 **0.0.20 → 0.0.31**, SSH 라이브러리 Paramiko를 **3.5.1 → 5.0.0**으로 갱신했다. pytest는 운영 요구사항에서 제거하고 개발 전용 요구사항의 **9.0.3**으로 갱신했다. [공식 근거·호환성 검토](DEPENDENCY_REMEDIATION.md)에 CVE별 사용 조건과 수정 근거를 기록했다.

최신 소스를 같은 자산·프로젝트 이름 `EOLWatch source`로 웹에서 재업로드했다. **작업 #10 → 분석 #10 → SBOM #20**, 구성요소 22개·CVE **0개**로 완료됐다. 분석 #5 → #10의 비교 결과는 계속 검출 0, 신규 0, **재분석 미검출 8, 구성요소 제거 1**이다. 제거 1건은 운영 의존성에서 분리한 pytest다. 이전 결과는 보존했으며 CVE 상태를 자동으로 완료 처리하지 않았다.

수정 ZIP: `reports/eolwatch-project-source.zip`, 소스·명세 64개 파일, 175,243바이트, SHA256 `36cd9ae08f354185b7f07492facf9e06b4f18aaf3da1c7052df4ae344c1fdf5d`. 이 숫자는 해당 시점의 소스 ZIP 분석 결과이며, 설치된 모든 전이 의존성·OS·컨테이너를 포함한 전체 취약점 부재를 뜻하지 않는다.

실제 웹에서 PDF·JSON을 다운로드했다. 브라우저·API 오류 0건이었다. 운영 이미지에서 새 라이브러리 버전과 pytest 미설치를 확인했다. Python 3.9의 기존 `.venv`는 보존하고 이후 검증은 Python 3.12 컨테이너를 사용한다.

근거: [313개 테스트와 의존성 검증](../reports/dependency-remediation-verification.json), [재분석 기록](../reports/source-remediation-verification.json), [전후 PDF](../reports/eolwatch-source-analysis-5-10.pdf), [전후 JSON](../reports/eolwatch-source-analysis-5-10.json), [비교 화면](../reports/source-remediation-comparison.png).

Paramiko 5.0.0 배포 후 두 VM의 strict 호스트 키 검증·인증과 수집 점검 #7·#8이 성공했다. 웹 SSH 프로젝트 작업 #11·#12도 분석 #11·#12, SBOM #21·#22로 성공했다. 협상 알고리즘은 양쪽 모두 ECDSA nistp256·AES128-CTR·HMAC-SHA256이었다. 이 SSH 회귀는 보존한 이전 소스 경로를 읽었으므로 해당 스냅샷의 CVE 9건이 유지된다. 수정 ZIP #20의 CVE 0건과 입력이 다르다. 점검은 성공했지만 당시 CPU 표본 100%에 따른 건강도 CRITICAL도 원래대로 기록했다.

[SSH 호환성 검증](../reports/paramiko5-ssh-verification.json)과 [최종 실행 환경 확인](../reports/final-runtime-verification.json)에 근거를 남겼다. 실제 API의 UTC 날짜가 2026-09-15인 시점에도 업무 기준일과 작업목록 `as_of`는 한국 날짜인 2026-09-16으로 일치했다.

## 실제 실패와 재시도

존재하지 않는 새 프로젝트 경로를 웹에서 분석한 작업 #8은 `APP_NOT_INSTALLED`로 실패했다. 분석·SBOM 번호는 생성되지 않았다. 해당 새 경로에 검증용 소스 사본 64개 파일을 배치하고 파일별 SHA256 일치를 확인한 뒤 웹에서 재시도했다.

재시도 작업 #9는 `retry_of_id=8`로 생성되어 분석 #9·SBOM #19에 성공 결과를 저장했다. 원래 작업 #8은 실패 이력으로 보존됐다. 브라우저 오류·예상하지 않은 API 실패는 없었다.

근거: [Python·재시도 기록](../reports/python-retry-verification.json), [실패 화면](../reports/project-path-failed.png), [재시도 성공 화면](../reports/project-path-retry-success.png).

## 관리 화면과 SBOM 상세

실제 Chrome에서 자산 등록·수정, 제품 날짜 편집·영향 자산 이동, 계약 등록·수정, 구성요소 개별 날짜 저장·제품 상속 복귀를 확인했다. 개별 날짜 변경 후에도 공통 제품 날짜와 원본 SBOM 해시는 유지됐다.

관리 화면 검증에는 명칭에 `검증용`을 붙인 별도 자산 #4, 제품 #1376~1378, 계약 #1, SBOM #16, 구성요소 #5418~5419를 사용했다. 날짜·가격·example.com URL은 검증 입력이며 실제 계약·제품 지원 정책이 아니다. 자산 모니터링은 꺼두었다.

기존 실제 SBOM #13에서는 MarkupSafe의 BSD-3-Clause 라이선스·관계·원본 JSON 다운로드를 확인했다. 기존 CVE 조치 #24503은 FIXED, revision 1, 이력 #1을 그대로 유지했다. 관리 브라우저 검증의 화면 오류·API 실패·전체 `/vulnerabilities` 조회는 모두 0건이었다.

근거: [관리 검증 기록](../reports/management-browser-verification.json), [구성요소 상세 화면](../reports/management-component-lifecycle-verification.png), [제품 영향 화면](../reports/management-product-impact-verification.png), [계약 화면](../reports/management-contract-verification.png), [작업목록 화면](../reports/management-browser-verification.png).

## 실제 OSV 재조회

먼저 로컬에서 SBOM #12·13의 전송 후보를 확인했다. 조회 대상은 공개 PyPI 패키지 `jinja2@3.1.4`, `jinja2@3.1.6`, `markupsafe@3.0.3`뿐이었다. 다른 패키지가 있으면 중단하도록 제한했고, 자산명·소스·키는 전송하지 않았다.

실제 API 조회에서 SBOM #12는 2개 패키지·CVE 3개, #13은 2개 패키지·CVE 0개였다. 각 SBOM의 버전 없는 루트 항목 1개는 조회에서 제외했다. Grype 원본 분석 #3·4의 해시, 기존 수동 FIXED·담당자·기한·revision·이력은 전후 동일했다.

근거: [OSV 실연동 검증](../reports/osv-live-verification.json). 최초 넓은 검증 요청은 외부 전송 위험으로 자동 승인 검토에서 차단됐으며, 로컬 자료로 공개 패키지 범위를 확인하고 제한한 요청이 승인된 뒤 실행했다.

## 실제 백업과 복원

`/opt/eolwatch/backups/eolwatch-runtime-20260915T144542Z-76c425a192bc`에 DB와 등록된 ZIP을 백업했다. PostgreSQL public 23개 테이블의 행 수·내용 SHA256을 임시 복원 DB와 대조했고 업로드 ZIP 해시도 일치했다. 임시 검증 DB는 삭제되어 잔존 0개다. 운영 DB로 복원하지 않았다.

root cron에 매일 백업·복원 검증을 등록했다. 서버 시간대가 UTC이므로 **03:20 UTC = 한국 시각 12:20**이다. cron 서비스는 실행 중이며 첫 예약 실행일은 2026-09-16이다. 정기 항목 설치와 명령의 실제 복원 성공을 확인한 것이며, 아직 도래하지 않은 최초 cron 실행까지 성공했다고 기록하지 않는다.

근거: [백업 실검증 기록](../reports/runtime-backup-verification.json), [백업 사용법](BACKUP_OPERATIONS.md).

최종 의존성 수정·재분석·SSH 회귀 후 `/opt/eolwatch/backups/eolwatch-runtime-20260915T151009Z-c9f81ca00e3e`에 다시 백업했다. 수정 전후 원본 ZIP 2개를 포함하며 23개 테이블 복원 검증, 완료 manifest 해시와 임시 DB 잔존 0개를 재확인했다. DB 덤프는 12,389,310바이트, ZIP 묶음은 350,200바이트다. [최종 백업 증거](../reports/final-backup-verification.json)를 확인한다.

## 설명 자료

[교수님용 전체 구조·웹 앱·시나리오](PROFESSOR_PROJECT_GUIDE.md), [현재 구현 현황](IMPLEMENTATION_STATUS.md), [API](API.md)를 함께 확인한다. 이전 데모 앱의 CVE 3건→0건과 이번 실제 프로젝트 소스의 9건은 서로 다른 범위·입력의 결과다.
