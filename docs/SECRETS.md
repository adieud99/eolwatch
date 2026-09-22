# 비밀값 관리 (.env, 키, 자격 증명)

코드 기준: 2026-09-22. 교수님 지적 "`.env`를 안전하게 다루는 방법을 생각하라"에 대한 답이다. 무엇이 비밀값인지, 어디에 두는지, 어떻게 보호하는지, 무엇이 남은 한계인지를 적는다.

## 1. 어떤 비밀값이 있나

| 이름 | 쓰는 곳 | 노출되면 |
|---|---|---|
| `JWT_SECRET` | 로그인 토큰 서명(api), 자격 증명 암호화 키 파생(api·worker, `CREDENTIAL_KEY`가 없을 때) | 위조 토큰으로 관리자 권한, 저장된 SSH 비밀번호·개인키 복호화 |
| `CREDENTIAL_KEY` | 서버별 SSH 비밀번호·개인키 암호화(Fernet) | 저장된 SSH 자격 증명 복호화 |
| `ADMIN_PASSWORD` | 최초 관리자 계정 생성 | 관리자 로그인 |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | AI 요약·선별·조치 가이드·수집 에이전트·라이브러리 참조 | 과금, 사용량 소진 |
| `DATABASE_URL` | DB 접속 문자열(비밀번호 포함) | DB 전체 |
| `secrets/eolwatch_ssh_key`, `secrets/known_hosts` | 관리 서버 키 방식 SSH | 대상 서버 접속 |

DB 안의 SSH 비밀번호·개인키는 평문이 아니라 위 키로 암호화된 값이다(`backend/app/services/ssh_auth.py`).

## 2. 지금 적용된 보호

### 기본값이 없다

`docker-compose.yml`은 `JWT_SECRET`과 `ADMIN_PASSWORD`를 `.env`에서 반드시 받는다. 없으면 `docker compose up`이 멈춘다.

```yaml
JWT_SECRET: ${JWT_SECRET:?JWT_SECRET is required (.env)}
ADMIN_PASSWORD: ${ADMIN_PASSWORD:?ADMIN_PASSWORD is required (.env)}
```

코드에도 관리자 비밀번호 기본값이 없다. `ADMIN_PASSWORD`가 비어 있으면 관리자 계정을 만들지 않고 경고만 남긴다(`backend/app/services/auth.py` `ensure_admin`). 이전에는 `Eolwatch!2026`이 코드·compose·README에 박혀 있었고 2026-09-22에 모두 제거했다. 테스트는 `backend/tests/conftest.py`에서 자기 값을 넣는다.

### 파일로 주입할 수 있다 (`*_FILE`)

환경변수 대신 파일 경로를 주면 파일 내용을 읽는다. Docker secrets·Kubernetes secret의 관례와 같고, `docker inspect`·프로세스 목록·크래시 덤프에 값이 찍히지 않는다.

```python
# backend/app/config.py
SECRET_FIELDS = ("jwt_secret", "credential_key", "admin_password", "openai_api_key", "anthropic_api_key", "database_url")
# JWT_SECRET_FILE=/run/secrets/jwt_secret → 파일 내용이 JWT_SECRET보다 우선
```

compose 예시:

```yaml
services:
  api:
    environment:
      JWT_SECRET_FILE: /run/secrets/jwt_secret
      ADMIN_PASSWORD_FILE: /run/secrets/admin_password
      OPENAI_API_KEY_FILE: /run/secrets/openai_api_key
    secrets: [jwt_secret, admin_password, openai_api_key]
secrets:
  jwt_secret: { file: ./secrets/jwt_secret }
  admin_password: { file: ./secrets/admin_password }
  openai_api_key: { file: ./secrets/openai_api_key }
```

`secrets/`는 `.gitignore`에 있어 저장소에 올라가지 않고 컨테이너에는 읽기 전용(`:ro`)으로 마운트된다.

### 저장소에 올라가지 않는다

`.env`, `secrets/*`, `backend/eolwatch.db`, `infrastructure/local-vm/runtime/*`는 `.gitignore`에 있다. `.env.example`에는 값이 비어 있다. 소스 ZIP을 만드는 `scripts/package-project-source.py`도 `.env`와 키를 넣지 않는다.

### 로그·응답·AI에 나가지 않는다

- API 응답은 `has_password`, `has_private_key`, 호스트 키 지문만 돌려준다(`routers/assets.py:42-48`).
- 검사 도구에 넘기는 환경변수는 `PATH, HOME, LANG, 프록시`뿐이다(`analysis_executor.py:514-523`).
- Git 토큰은 clone 한 번에만 쓰고 작업 기록에서 지운다.
- AI에는 주소·호스트 이름·계정·인스턴스 번호·비밀번호를 보내지 않는다. 화면의 "AI에 보내는 데이터 보기"로 전문을 확인할 수 있다(`docs/AI.md`).

## 3. 운영자가 할 일

1. `.env`를 만들 때 `openssl rand -base64 48`로 `JWT_SECRET`과 `CREDENTIAL_KEY`를 **서로 다른 값**으로 만든다. 같은 키를 두 용도에 쓰면 하나가 새면 둘 다 샌다.
2. `chmod 600 .env`, `chmod 700 secrets && chmod 600 secrets/*`.
3. 운영 서버에서는 `.env` 대신 `*_FILE`과 Docker secrets(또는 클라우드 비밀 관리 서비스)를 쓴다.
4. `CREDENTIAL_KEY`를 바꾸면 저장된 SSH 비밀번호·개인키를 풀 수 없으므로, 바꾸기 전에 서버별 자격 증명을 다시 입력할 계획을 세운다.
5. 백업(`scripts/backup-runtime.py`)에는 DB 덤프가 들어가고 그 안에 암호화된 자격 증명이 있다. 백업 디렉터리 권한을 `.env`와 같은 수준으로 지킨다. `.env`와 키 파일은 백업에 포함되지 않으므로 따로 보관한다.
6. 대상 서버에는 검사 전용 계정을 만들고 `sudo`는 `apt-get update`에만 허용한다(`package_updates.py`가 `sudo -n apt-get update`만 시도한다).

## 4. 남은 한계 (솔직하게)

- 암호화 키가 관리 서버에 평문 파일로 있다. 관리 서버의 루트가 뚫리면 DB의 자격 증명도 풀린다. HSM·KMS 연동은 없다.
- 키 교체(rotation) 기능이 없다. 바꾸려면 자격 증명을 다시 입력해야 한다.
- 브라우저는 JWT를 localStorage에 둔다. XSS가 있으면 토큰이 새므로 HttpOnly 쿠키가 더 안전하다. 8시간 만료로 노출 시간을 줄였다.
- 로그인 실패 횟수 제한이 없다.
