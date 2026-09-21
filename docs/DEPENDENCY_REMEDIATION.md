# 자체 소스 분석으로 확인한 의존성 보완

검토일: 2026-09-16 KST. 기준 결과는 실제 업로드한 EOLWatch 소스 ZIP의 분석 run 5 / SBOM 14이다. 선언 파일에서 구성요소 23개와 취약점 9건을 발견했다. 로컬 분석 결과와 공식 패키지 공지를 대조했으며, 소스나 비공개 SBOM을 외부 취약점 서비스로 전송하지 않았다.

## 변경한 직접 의존성

| 패키지 | 기존 버전 | 적용 버전 | 사용 위치와 조치 |
| --- | --- | --- | --- |
| python-multipart | 0.0.20 | 0.0.31 | 운영 API의 ZIP·CSV 업로드 및 폼 파싱. 아래 7건의 수정 버전을 포함한다. |
| pytest | 8.4.1 | 9.0.3 | 테스트 도구. 운영 `requirements.txt`에서 제거하고 `requirements-dev.txt`로 분리했다. |
| Paramiko | 3.5.1 | 5.0.0 | 운영 SSH 점검과 앱 분석. RSA/SHA1 서명 검증·생성을 제거한 공식 릴리스로 갱신했다. |

`requirements-dev.txt`는 `-r requirements.txt`와 `pytest==9.0.3`을 포함한다. API와 분석 worker는 운영 의존성만 설치한다. CI는 Python 3.12에서 개발 의존성을 설치한다. 프런트엔드 잠금 파일과 대조했을 때 이번 9건은 모두 Python 패키지였다.

## python-multipart 7건의 공식 근거

| CVE | 공지의 수정 버전 | 조건과 코드 검토 |
| --- | --- | --- |
| [CVE-2026-24486](https://github.com/Kludex/python-multipart/security/advisories/GHSA-wp53-j4wj-2cfg) | 0.0.22 이상 | 비기본 설정 `UPLOAD_DIR`와 `UPLOAD_KEEP_FILENAME=True`에서 파일 경로 조작. 앱은 해당 라이브러리 설정을 사용하지 않고 ZIP을 콘텐츠 해시 이름으로 저장한다. 공지의 Patched versions 필드를 기준으로 기록했다. |
| [CVE-2026-42561](https://github.com/Kludex/python-multipart/security/advisories/GHSA-pp6c-gr5w-3c5g) | 0.0.27 | multipart 파트 헤더의 개수·크기 제한 누락으로 CPU 소진. FastAPI 업로드 파싱 경로에 관련된다. |
| [CVE-2026-40347](https://github.com/Kludex/python-multipart/security/advisories/GHSA-mj87-hwqh-73pj) | 0.0.26 | 큰 multipart preamble·epilogue 처리에 의한 서비스 거부. 업로드 파싱 경로에 관련된다. |
| [CVE-2026-53539](https://github.com/Kludex/python-multipart/security/advisories/GHSA-5rvq-cxj2-64vf) | 0.0.30 | 세미콜론으로 구성된 URL 인코딩 폼의 비효율적인 파싱. Starlette/FastAPI의 폼 파서에 관련된다. |
| [CVE-2026-53537](https://github.com/Kludex/python-multipart/security/advisories/GHSA-vffw-93wf-4j4q) | 0.0.30 | Content-Disposition 확장 매개변수 해석 차이. 앱은 업로드 파일명을 저장 경로로 사용하지 않지만 파서 버전을 갱신한다. |
| [CVE-2026-53538](https://github.com/Kludex/python-multipart/security/advisories/GHSA-6jv3-5f52-599m) | 0.0.30 | 세미콜론을 폼 구분자로 취급해 다른 계층과 매개변수 해석이 달라질 수 있다. |
| [CVE-2026-53540](https://github.com/Kludex/python-multipart/security/advisories/GHSA-v9pg-7xvm-68hf) | 0.0.31 | `parse_form`이 음수 Content-Length를 처리할 때 입력 전체를 읽을 수 있다. 앱은 이 고수준 함수를 직접 호출하지 않는다. |

이는 패키지 탐지 결과와 사용 경로를 검토한 기록이다. 각각의 공격을 운영 서비스에서 재현하거나 일괄적으로 VEX의 영향 없음 판정을 내린 기록은 아니다.

[0.0.31 배포 메타데이터](https://pypi.org/project/python-multipart/0.0.31/)는 Python 3.10 이상을 요구한다. [공식 릴리스](https://github.com/Kludex/python-multipart/releases/tag/0.0.31)는 헤더 제한과 Content-Length 검증 변경을 기록한다. 개발·운영 검증 기준은 **Python 3.12**로 맞춘다. 기존 로컬 Python 3.9 `.venv`는 보존하며 이 환경에 새 requirements를 설치하지 않는다.

## pytest와 Paramiko의 영향

pytest의 [공식 9.0.3 변경 내역](https://docs.pytest.org/en/stable/changelog.html#pytest-9-0-3-2026-04-07)은 임시 디렉터리 처리 취약점 CVE-2025-71176의 수정을 명시한다. 앱 코드가 pytest를 실행할 필요가 없어 운영 이미지에서 제외했다. 개발 환경에서는 수정 버전을 설치한다.

기준 Grype 결과는 Paramiko CVE-2026-44405의 수정 버전을 비워 두었다. 그러나 [공식 5.0.0 변경 내역](https://www.paramiko.org/changelog.html)과 [RSA/SHA1 제거 커밋](https://github.com/paramiko/paramiko/commit/a4489456b6f65281e172380cc4826cee5e851dbb)은 해당 동작의 제거를 확인해 준다. [5.0.0 배포 메타데이터](https://pypi.org/project/paramiko/5.0.0/)는 2026-05-09 릴리스와 Python 3.9 이상 지원을 확인해 준다.

`backend/app/services/collector.py`와 `analysis_executor.py`는 `SSHClient.connect`를 사용한다. 수정에는 클라이언트의 호스트 키 검증도 포함되므로, SSH 서버로 동작하지 않는다는 이유만으로 영향 없음으로 분류하지 않았다.

**Paramiko 3.5.1 → 5.0.0은 메이저 업그레이드이다.** 4.0에서 DSA/DSS 지원이 제거되었고, 5.0에서 RSA/SHA1 서명, SHA1 기반 Diffie-Hellman 키 교환, GSSAPI 지원이 제거되었다. RSA 키 자체는 SHA2 서명과 함께 사용할 수 있다. 레거시 알고리즘만 지원하는 사용자 서버는 연결에 실패할 수 있으므로 대상 서버에서 Ed25519 또는 RSA/SHA2 등 지원 알고리즘을 준비해야 한다. 검증 대상 서버의 기존 신뢰 키와 Ed25519 사용자 키를 유지하며 실제 SSH 호환성은 배포 후 다시 확인한다.

## 테스트 재현

프로젝트 루트에서 실행한다. Docker의 `test` stage는 Python 3.12와 개발 의존성을 설치한다. 테스트는 별도 컨테이너의 임시 SQLite DB를 사용한다. 아래 실행은 필요한 소스·샘플만 읽기 전용으로 마운트하며, 운영 DB·업로드 볼륨·`.env`·SSH 키·Docker 소켓을 마운트하지 않는다.

같은 구성을 실행하는 관리 스크립트는 `./scripts/test-backend.sh`이다. 직접 실행하려면 다음 명령을 사용한다.

```sh
docker build --target test -t eolwatch-backend-test ./backend
docker run --rm --network none \
  --mount "type=bind,source=$PWD/backend,target=/workspace/backend,readonly" \
  --mount "type=bind,source=$PWD/samples,target=/workspace/samples,readonly" \
  --mount "type=bind,source=$PWD/scripts,target=/workspace/scripts,readonly" \
  --mount "type=bind,source=$PWD/pytest.ini,target=/workspace/pytest.ini,readonly" \
  eolwatch-backend-test
```

`WORKDIR=/workspace`에서 루트 `pytest.ini`가 `backend`를 Python 경로로 지정한다. 샘플과 스크립트를 읽는 테스트도 이 디렉터리 구성을 사용한다. 운영 이미지의 pytest 제외 여부는 다음과 같이 확인할 수 있다.

```sh
docker build --target api -t eolwatch-backend-api-check ./backend
docker run --rm --network none eolwatch-backend-api-check \
  python -c "import importlib.util; assert importlib.util.find_spec('pytest') is None"
```

Docker 없이 개발하려면 기존 `.venv`와 별도로 Python 3.12 환경을 만든다.

```sh
python3.12 -m venv .venv312
.venv312/bin/python -m pip install -r backend/requirements-dev.txt
.venv312/bin/python -m pytest -q
```

## 검증 범위

격리 컨테이너의 설치 버전·전체 테스트·운영 이미지 검증 증거는 `reports/dependency-remediation-verification.json`에 기록한다. 배포 후 실제 SSH 점검·분석과 수정한 소스 ZIP의 재분석 비교는 [프로젝트 확장 검증 기록](PROJECT_EXPANSION_VERIFICATION.md)에 기록한다.

2026-09-16 00:01 KST에 Python 3.12.14 / pytest 9.0.3으로 **313개 전체 테스트가 37.20초에 통과**했다. Starlette의 anyio 폐기 예정 별칭 경고 1건이 있었으며, `pip check`는 정상이다. 별도로 빌드한 API 이미지에서 multipart 0.0.31 / Paramiko 5.0.0 설치, pytest 미설치, `RSAKey.HASHES`의 SHA1 알고리즘 제거를 확인했다. 테스트는 실제 서버와 통신하지 않으므로 배포 후 SSH 재확인과 구분한다.

소스 ZIP의 선언 파일 분석은 설치된 모든 Python 전이 의존성이나 OS 패키지를 보장하지 않는다. 이번 9건이 사라지는 결과를 애플리케이션 전체의 취약점 부재로 해석하지 않는다. Grype 데이터와 upstream 수정 공지가 다를 때도 원래 분석 결과를 덮어쓰지 않고 소스·버전과 재분석 결과를 함께 남긴다.
