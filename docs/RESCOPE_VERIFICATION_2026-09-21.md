# 재범위화 검증 기록 (2026-09-21)

개발 및 인프라 취약점 검사 솔루션으로 재구성한 코드(`73c10b5`, `d0592ac`)를 실제로 실행해 확인한 기록이다. 맥에서 PostgreSQL 16 컨테이너, 기존 API·worker 이미지에 새 코드를 마운트해 실행했다. 브라우저 대신 API로 흐름을 확인했으며, 화면 검증과 실제 서버 대상 인프라 검사는 남아 있다.

## 마이그레이션

| 확인 | 결과 |
|---|---|
| `alembic upgrade head` (빈 PostgreSQL 16) | 초기 → `d2f8c4a71e9b` 전체 체인 통과 |
| `alembic check` | 모델과 DB 일치 (No new upgrade operations) |
| `downgrade c1e4f7a9b2d6` → `upgrade head` → `check` | 통과 |

## 개발 검사 (소스 ZIP)

| 단계 | 결과 |
|---|---|
| 대상 등록 `POST /api/assets` | 201, 접속 정보 없는 대상 등록 가능 |
| ZIP 업로드 `POST /api/analyses/assets/1/uploads` (requirements.txt에 flask 2.2.2·jinja2 3.1.4·requests 2.31.0·werkzeug 2.2.2) | 작업 #1 QUEUED → 40초 후 SUCCESS |
| 검사 #1 결과 | Syft 1.51.1 → SPDX → Grype 0.118.0, 구성요소 5개, CVE 17건, 수정 버전 표시 |
| 저장 ZIP 재검사 `POST /api/analyses/uploads/{id}/jobs` | 작업 #2 SUCCESS, 검사 #1과 비교 시 계속 검출 17·변화 0 |
| 저장 ZIP 원본 다운로드 | 업로드 파일과 바이트 동일 |
| 수정 버전 ZIP 업로드 (flask 3.1.1·jinja2 3.1.6·requests 2.32.4·werkzeug 3.1.6) | 작업 #3 SUCCESS |
| 전후 비교 `GET /api/analyses/1/compare/3` | 재검사 미검출 15, 계속 검출 2, 새로 검출 0 |
| 비교 보고서 | PDF 106,542바이트, JSON 7,221바이트 |
| 실행 중 취소 | 작업 #4 COLLECTING 상태에서 취소 → CANCEL_REQUESTED → CANCELLED (`USER_CANCELLED`) |
| 조치 기록 `POST /api/vulnerabilities/1/actions` | FIXED, 검사 #3 근거, 이력 조회 가능. 오래된 revision으로 재요청 시 409 |
| 대시보드 | `open_cves` 17 → 조치 후 미완료 작업목록 감소, `current_open_cves`는 최신 검사 기준 |

## 개발 검사 추가 입력 (같은 날 추가)

| 단계 | 결과 |
|---|---|
| 의존성 파일만 업로드 (`requirements.txt`, 수정 버전 4개) | 작업 #1 SUCCESS, 범위 `source-zip:orders-api`, 구성요소 5개, CVE 2건. 보관 파일은 한 항목 ZIP, 다운로드 이름 `requirements.txt.zip` |
| Git 저장소 `https://github.com/pallets/flask` 태그 `3.0.0` | 작업 #2 SUCCESS, 범위 `source-git:flask`, 커밋 `735a4701…` 기록, 구성요소 32개(requirements/*.txt·GitHub Actions), CVE 13건 |
| 존재하지 않는 저장소 + 더미 토큰 | FAILED `GIT_CLONE_FAILED`, DB 스냅샷과 worker 산출물 어디에도 토큰 문자열 없음 |
| 잘못된 요청 (http://, 계정 포함 URL, `--`로 시작하는 브랜치) | 422 |

worker 이미지에 `git`이 필요하다(Dockerfile analysis-worker 단계에 추가).

## 정식 이미지 빌드와 개발 스택 (같은 날 재시도)

| 확인 | 결과 |
|---|---|
| `docker compose build` | api·worker·web 이미지 빌드 성공 (앞선 시도는 Docker Hub 다운로드 지연으로 실패) |
| `docker compose up -d` | 기존 맥 개발 DB(`eolwatch_postgres_data`)에서 `c1e4f7a9b2d6 → d2f8c4a71e9b` 마이그레이션 자동 적용, api healthy, worker에 git 2.47 |
| 정식 스택에서 Git 검사 (`pallets/flask` 3.0.0) | SUCCESS, 커밋 `735a4701…`, 구성요소 32개, CVE 13건 |
| 웹 번들 (<http://127.0.0.1:8080>) | 개발 검사·인프라 검사·검사 기록·Git 저장소 문구 포함, 제거한 메뉴 문구 없음 |
| `sh scripts/test-backend.sh` (격리 컨테이너, Python 3.12) | 363 passed |

## 인프라 검사 (서버)

| 단계 | 결과 |
|---|---|
| 서버 등록 (IP·SSH 계정·포트) | 201 |
| SSH 점검 `POST /api/checks/assets/2/run` (도달 불가 IP) | FAILED / CONNECT / TIMEOUTERROR 로 단계·원인 표시 |
| 점검 목록 `GET /api/checks` | `server_info` 필드 포함 (성공 시 하드웨어·OS·가상화·클라우드·IP·포트·서비스) |

실제 서버에 대한 SSH 점검·설치 패키지 검사·서버 앱 경로 검사·정기 검사는 실습 VM이 켜져 있을 때 확인한다. `server_info` 파서는 단위 테스트(`backend/tests/test_collector.py`)로 확인했다.

## 권한·감사

조회자 계정은 이력 조회 200, ZIP 업로드 403. 모든 변경 요청이 감사 로그에 사용자·경로·응답 코드로 남았다.

## 남은 검증

1. 브라우저에서 개요 → 개발 검사 → 검사 기록(CVE 결과·조치, 전후 비교, 의존성 목록) 순서로 같은 흐름을 확인한다.
2. 실습 VM을 켜고 인프라 검사: 서버 등록 → SSH 점검(서버 정보 카드) → OS 패키지 검사 → 서버 앱 경로 검사 → 정기 검사 등록.
