# 현재 상태 검증 기록

검증일: 2026-09-15 (KST)

## 결론

최신 작업 트리의 기본 테스트·빌드·DB 검증과 로컬 서비스 기동 확인을 마쳤다. 로컬 대상 VM 2대의 실제 SSH 수집 및 SPDX 생성도 성공했다. 다음 단계는 SBOM 생성·취약점 분석 도구 연동이다.

## 검증 결과

| 항목 | 결과 |
|---|---|
| 백엔드 `../.venv/bin/python -m pytest -q` | 11개 통과 |
| 프런트엔드 `npm test` | 2개 통과 |
| 프런트엔드 `npm run build` | 통과 |
| 개발·운영 Compose 설정 | 통과, 운영 설정은 검증용 비밀값 사용 |
| 임시 SQLite DB 마이그레이션 | upgrade head → check → downgrade base → upgrade head 통과 |
| 맥 Docker 이미지 재빌드·기동 | API·web·worker 정상, 기존 PostgreSQL 볼륨 유지 |
| 맥·controller VM PostgreSQL | revision `7c61b9af20d4`, 모델과 마이그레이션 차이 없음 |
| 맥·controller VM 백엔드 소스 | 각각 `backend/app` 35개 파일 해시가 현재 작업 트리와 일치 |
| VirtualBox | controller·target-01·target-02 실행 중 |
| controller VM 컨테이너 | API·web·worker 실행 중, PostgreSQL healthy |
| 두 웹 주소 `/health` | JSON `{"status":"ok"}` 확인 |
| 두 서비스 인증·조회 | 비인증 자산 조회 401, 로그인·자산 목록·대시보드 조회 성공 |
| 실제 SSH 수집 | 로컬 대상 VM 2대 성공 |
| 실제 수집 결과의 SPDX 생성 | 두 건 모두 SPDX 2.3 생성·가져오기 성공, 가져오기 경로에서 공식 스키마 검증 수행 |
| Nginx·셸 문법 및 diff 공백 검사 | 통과 |

SQLite downgrade 검증은 임시 DB에서만 수행했다. 실제 서비스 DB를 다운그레이드하거나 초기화하지 않았다.

## 실제 수집 증거

controller VM의 서비스 DB에 다음 이력을 추가했다.

| 자산 | 대상 IP | 점검 ID | SBOM ID | 수집 패키지 | SBOM 구성요소 |
|---|---|---:|---:|---:|---:|
| LAB-VM-01 | 10.77.0.21 | 5 | 8 | 669 | 670 |
| LAB-VM-02 | 10.77.0.22 | 6 | 9 | 669 | 670 |

SBOM 구성요소 수에는 수집 패키지 외에 자산을 나타내는 루트 항목 1개가 포함된다. CPU·메모리·디스크 측정값도 점검 결과에 저장됐다. 이번 검증은 전용 키와 호스트 키 검사 설정을 사용하는 기존 수집 API를 통해 실행했다.

## 발견하고 처리한 문제

### 웹 헬스체크가 HTML을 정상으로 오인

기존 Nginx는 `/health`를 API로 전달하지 않아 SPA의 `index.html`을 HTTP 200으로 반환했다. 상태·배포 스크립트는 HTTP 성공 여부만 보고 API가 정상이라고 판단할 수 있었다.

- `frontend/nginx.conf`: 정확한 `/health` 경로를 API에 프록시한다.
- `infrastructure/local-vm/status.sh`, `deploy-to-lab.sh`: 응답 JSON의 `status`가 `ok`인지 검사하고 요청에 5초 제한을 둔다.
- 상태 스크립트는 웹/API 확인 실패 시 종료 코드 1을 반환한다.
- 맥 Docker와 controller VM 웹 컨테이너에 수정된 Nginx 설정을 반영했다.

### 맥 Docker 실행본이 이전 코드

기존 맥 Docker의 DB revision은 `91c6d6d4a2f1`이었으며 SBOM·수집·취약점 서비스 코드도 현재 파일과 달랐다. `docker compose up --build -d`로 현재 소스를 반영하고 최신 마이그레이션 및 소스 일치를 확인했다.

controller VM은 이미 최신 백엔드였다. 웹 헬스체크 설정을 반영하기 위해 해당 웹 컨테이너만 재빌드했다.

## 접속 주소

- 로컬 VM 시연 서비스: <http://127.0.0.1:18080>
- 맥 Docker 서비스: <http://127.0.0.1:8080>
- 맥 Docker API 문서: <http://127.0.0.1:8000/docs>

두 서비스는 별도 DB를 사용한다. 위 실제 수집 이력은 VM 시연 서비스에서 확인한다.

## 이번 검증의 범위와 다음 작업

- 검증은 기존 자체 SSH 수집기와 SPDX 생성 경로를 대상으로 했다. Syft·Grype 등 외부 분석 도구 연동 완료를 의미하지 않는다.
- 실제 CVE 대조 정확성, 수정 버전 선택, 재분석 후 조치 완료 판단은 후속 단계다. 이번에는 외부 OSV 조회를 추가 실행하지 않았다.
- 프런트엔드는 자동 테스트·빌드 및 HTTP 연결을 확인했다. 실제 브라우저에서 모든 화면을 조작한 전체 시연 검증은 후속 단계다.
- worker 프로세스 실행은 확인했으나 예약 시각의 자동 수집 실행까지 기다려 검증하지 않았다.
- AWS 변경·Black Duck 연동·Teams 전송·백업 복구 훈련은 수행하지 않았다.
- 현재 단계의 기본 검증은 통과했다. 다음은 대상 1대의 실제 SBOM 생성·취약점 분석 도구 결과를 EOLWatch로 연결하는 작업이다.
