# EOLWatch 프로젝트 요약서

작성일 2026-09-22 · 코드 기준 `main` · 교수님 8단계 발표 순서(개요 → 솔루션 전체 구성도 → 시스템 구성도 → 서비스 구성도 → 서비스 설명 → 인프라 설명 → 추가 서비스 → 마무리)를 따른다.

## 1. 개요

**EOLWatch는 개발 소스와 운영 서버의 취약점(CVE)을 검사하고, 그 결과를 "지금 급한 것"부터 보이게 정리해 조치와 전후 비교까지 한곳의 기록으로 관리하는 개발·인프라 취약점 검사 솔루션이다.**

| 축 | 사용자가 하는 일 | 솔루션이 하는 일 | 결과 |
|---|---|---|---|
| 개발 검사 | 소스 ZIP·의존성 파일·Git 주소를 올린다 | Syft로 SBOM(SPDX 2.3) 생성, Grype로 취약점 DB 대조 | 라이브러리별 CVE·수정 버전·심각도 |
| 인프라 검사 | 서버 주소·SSH 계정을 등록한다 | SSH로 서버 정보 수집, Syft 복사·실행으로 설치 패키지 SBOM, Grype 대조, apt 대조 | 서버 정보, OS 패키지 CVE, 실제 악용 확인(KEV)·악용 확률(EPSS) |
| 검사 기록 | 과거 검사를 찾아본다 | 이력·CVE별 접기·조치 기록·AI 선별·전후 비교·PDF/JSON | 무엇을 보고 무엇을 고쳤는지 |

가져다 쓴 도구는 Syft 1.52.0과 Grype 0.119.0(둘 다 Apache-2.0)이고, 그 앞뒤의 모든 것(입력·SSH 접속·작업 큐·원본 검증·CVE 정리·우선순위·AI 연결·조치·비교·보고서·화면)을 직접 만들었다.

## 2. 솔루션 전체 구성도

```text
사용자 브라우저 → web(nginx) → api(FastAPI) ⇄ db(PostgreSQL)
                                     │                ▲
                              SSH 점검(동기)        결과 저장
                                     ▼                │
                                 대상 서버 ◀── SSH·SFTP ── worker(Syft·Grype·apt 대조)
api·worker ── HTTPS(식별자 제거한 압축본) ──▶ AI 제공자 (선택)
```

관리 서버 1대(Docker Compose 컨테이너 4개)가 여러 대상 서버를 검사한다. 대상에는 상주 프로그램이 없다.

## 3. 시스템 구성도

| 구성 | 역할 | 기술 |
|---|---|---|
| web | 정적 화면, `/api/` 프록시(요청마다 주소 재조회, 600 MB 업로드) | nginx 1.27, React 19, Vite |
| api | 인증(PBKDF2·JWT)·권한(ADMIN/VIEWER)·감사 로그, 서버 등록, ZIP 검증·보관, SSH 점검, 결과 조회, 조치, 비교·보고서, AI | FastAPI 0.116, SQLAlchemy 2, Alembic |
| worker | 3초 주기 DB 큐(`FOR UPDATE SKIP LOCKED`), SSH 수집, SPDX 변환, Grype, apt 대조, 원자적 저장, 일일 SSH 점검 | APScheduler, Paramiko, Syft, Grype |
| db | 서버·작업·SBOM·CVE·조치·감사·AI 기록 | PostgreSQL 16 |
| 볼륨 | ZIP 원본, 작업 산출물, Grype DB 캐시 | Docker volumes |
| 비밀값 | `.env` 또는 `*_FILE`(Docker secrets), DB 안 자격 증명은 Fernet 암호화 | `docs/SECRETS.md` |

## 4. 서비스 구성도 (화면)

| 화면 | 내용 |
|---|---|
| 개요 | 탐지 CVE 총계와 심각도 막대, 5개 지표(대상·최신 미조치·전체 미조치·수집 실패·SBOM), 대상별 최근 검사 |
| 개발 검사 | 대상 만들기, ZIP·의존성 파일·Git 검사, 진행 상태 |
| 인프라 검사 | 서버 등록·수정, SSH 점검(서버 정보·수집 에이전트), 취약점 검사, 서버 상세(의존성·타임라인) |
| 검사 기록 · 검사 이력 | 검색·페이지, 이전/이후 선택 |
| 검사 기록 · CVE 결과·조치 | 결과 표(전체/고칠 수 있음/KEV/EPSS), 구성요소별·CVE별 보기, 조치 관리, **AI 선별**, **AI 조치 가이드**, AI 요약, 원본 |
| 검사 기록 · 의존성 목록 | SBOM 구성요소 검색·상세·원본 다운로드 |
| 검사 기록 · 전후 비교 | 계속/새로/미검출/제거, PDF·JSON |

## 5. 서비스 설명 (개발 검사 흐름)

ZIP 업로드 → 스트리밍 해시·경로·압축률 검증 → `<sha256>.zip` 보관 → 작업 큐 → worker가 풀어 `syft scan` → SPDX 2.3 → `grype sbom:` → 저장 → 결과 화면 자동 이동. 잠금 파일이 없는 소스는 AI가 import 문과 의존성 파일에서 라이브러리·버전을 추정해(표시: "버전 추정") 같은 경로로 검사한다. 빌드·설치·실행은 하지 않는다.

검증 기록: EOLWatch 자체 소스 검사 #5 → 의존성 보완 → #10에서 CVE 9 → 0 (2026-09-15).

## 6. 인프라 설명 (인프라 검사 흐름)

서버 등록(비밀번호 / 개인키 첨부 / 관리 서버 키, 호스트 키 고정) → SSH 점검(읽기 전용 명령 20여 개 + AI가 고른 카탈로그 명령) → 취약점 검사(`uname -sm` → Syft 복사·체크섬 → `syft scan dir:/` → `/etc/os-release` → `apt list --upgradable`) → worker에서 SPDX·Grype(`--distro`, CPE 대조 끔) → CVE 번호 기준 집계, 커널/수정판/KEV/EPSS 분리, apt 대조.

검증 기록(2026-09-22): srv-my(EC2, Ubuntu 26.04) CVE 5,150 중 커널 4,778, 실제 악용 확인 2, 지금 고칠 수 있음 2. Ubuntu 공식 추적기와 80건 표본 대조 78건 일치(2건은 DB 하루 지연). 전체 업데이트한 실습 VM 재검사 3,904 → 3,896(apt가 올릴 수 있다고 한 8건만 사라짐, 커널 3,570은 Ubuntu 미수정). 자세한 근거는 `docs/KERNEL_CVE_VERIFICATION_2026-09-22.md`.

## 7. 추가 서비스

| 서비스 | 내용 | 근거 |
|---|---|---|
| 우선순위 | CVE마다 EPSS·CISA KEV·risk 저장, 결과 표와 배지로 "실제 급한 것" 표시, CVE별 보기 정렬 KEV → 심각도 → EPSS | `services/analysis.py`, `cve_breakdown.py` |
| AI 선별 | KEV·EPSS·수정판·심각도로 고른 후보 40건과 서버 사실만 보내 해당/확인 필요/해당 없음 가능성 + 조치 한 줄. 조치 상태는 사람이 바꾼다 | `services/ai_triage.py`, `docs/AI.md` |
| AI 조치 가이드 | CVE 하나의 조치 명령·재시작·확인 방법 | 같음 |
| AI 데이터 최소화 | 주소·호스트명·계정·인스턴스 번호·비밀번호 미전송, "AI에 보내는 데이터 보기"로 전문 확인 | `docs/AI.md` |
| 토큰 다이어트 | 요약 입력 82% 감소, 추론 토큰 끔(1,651 → 260) | `docs/TOKEN_DIET.md` |
| 권한·감사 | ADMIN/VIEWER, 성공한 변경·조치 감사 로그 | `middleware.py` |
| 백업 | DB + ZIP 원본 묶음, 임시 DB 복원 검증, 일일 cron | `scripts/backup-runtime.py` |
| 호환성 | Ubuntu·Debian(dpkg) 검사, x86_64·arm64, 도구 없는 배포판용 대체 명령 | `collector.py`, `analysis_executor.py` |

## 8. 마무리

- **판단 기준**: Grype 결과는 배포판이 공개한 패키지 버전 기준의 매칭이다. 미검출은 조치 완료가 아니고, "수정판 없음"은 감시 대상이며, KEV와 "지금 고칠 수 있는 CVE"가 조치 대상이다.
- **범위 밖**: 컨테이너 이미지, 자동 패치, 조직별 분리 SaaS, 클라우드 계정 API 연동. 타깃층과 라이선스는 `docs/LICENSES_AND_TARGET.md`, 실사용 절차는 `docs/PRACTICAL_USE.md`, 스캐너 대안은 `docs/SCANNER_OPTIONS.md`.
- **수치**: 백엔드 테스트 316개, 프런트 95개 통과(2026-09-22). 코드 규모 약 9,500줄(라우터·서비스·화면).
