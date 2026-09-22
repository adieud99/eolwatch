# VirtualBox 로컬 개발·시연 환경

현재 웹 분석 MVP는 노트북의 관리 VM 1대와 대상 VM 2대로 실행한다. AWS·Black Duck 계정은 필요하지 않다. 분석 흐름은 [전체 구조](../../docs/ARCHITECTURE.md), 사용법은 [웹 분석 안내](../../docs/WEB_ANALYSIS.md)를 따른다. 이 환경이 실행된다는 사실이 프로젝트 전체 개발 완료를 뜻하지는 않는다.

| VM | 내부 주소 | 호스트 SSH | 역할 |
|---|---|---:|---|
| eolwatch-controller | 10.77.0.10 | 12222 | `/opt/eolwatch`의 웹·API·worker·PostgreSQL |
| eolwatch-target-01 | 10.77.0.21 | 12223 | LAB-VM-01, Ubuntu·고정 Python 데모 앱 분석 |
| eolwatch-target-02 | 10.77.0.22 | 12224 | LAB-VM-02, Ubuntu 설치 패키지 분석 검증 |

- 실제 시연 웹: <http://127.0.0.1:18080>.
- 맥 Docker 개발 웹: <http://127.0.0.1:8080>. 관리 VM과 **별도 DB**다.
- VM 사이는 `eolwatch-lab` 내부망, 외부 패키지·취약점 DB 다운로드는 NAT를 사용한다.
- 로그인 계정은 관리 VM `.env`의 `ADMIN_USERNAME`/`ADMIN_PASSWORD`로 만들어진다(기본값 없음).

## 1. 이미 만든 환경에서 재개

프로젝트 루트에서 확인한다.

```bash
./infrastructure/local-vm/status.sh
```

VM이 꺼져 있으면 VirtualBox에서 기존 세 VM을 시작한다. 기존 DB·분석 이력을 확인하려는 작업에 생성·초기 설정 스크립트를 다시 실행할 필요는 없다.

브라우저에서 `작업 대상`의 LAB-VM-01·02를 확인한다. `CVE 조치`에서 저장된 분석 #3 → #4, SBOM #12 → #13을 비교할 수 있다. 이는 LAB-VM-01의 **데모 앱 범위** Jinja2 3.1.4 → 3.1.6 결과다. 앱 CVE 3건이 재분석에서 미검출됐으며 전체 OS의 위험 해소를 뜻하지 않는다.

현재 데모 앱은 수정 버전 3.1.6 상태다. VM을 재부팅하면 앱 프로세스는 자동 시작하지 않지만 가상환경은 남는다. 원본·비교 PDF·JSON은 [조치 검증](../../docs/archive/REMEDIATION_VERIFICATION_2026-09-15.md)과 [보고서 검증](../../docs/archive/COMPARISON_REPORT_VERIFICATION_2026-09-15.md)을 확인한다.

## 2. 새 환경을 처음 만들 때

macOS·VirtualBox와 `hdiutil`을 사용하는 초기 구성이다. Ubuntu 24.04 ARM64 이미지를 내려받아 SHA-256을 확인한다.

```bash
cd infrastructure/local-vm
./create-lab.sh
./deploy-to-lab.sh
./status.sh
```

`create-lab.sh`는 `eolwatch-` VM·SSH 키·cloud-init 자료를 만든다. 기존 다른 프로젝트 VM은 생성 대상이 아니다. 런타임 디스크·키·캐시는 Git에서 제외한다.

`deploy-to-lab.sh`는 **초기 배포용**이다. 소스 전송 외에도 `.env` 작성, SSH 키 배치·known_hosts 수집, 디렉터리 권한 설정, 컨테이너 빌드와 합성 데이터 입력을 수행한다. 기존 운영 설정·DB를 유지하는 일반 코드 갱신 명령으로 사용하지 않는다. 초기 연결 이후에는 호스트 키를 확인하고 엄격한 검증으로 접속한다.

로컬 실습용 `eolwatch` 계정에는 VM 관리 편의를 위한 sudo 권한이 있다. 이를 최소 권한 운영 계정으로 설명하지 않는다.

## 3. 기존 환경에 코드만 갱신

현재의 안전한 수동 갱신 절차는 [NEXT_SESSION.md의 코드 갱신](../../docs/NEXT_SESSION.md#코드-작업-후-검증배포)을 따른다.

1. 변경한 소스·필요한 의존성·마이그레이션 파일만 묶는다.
2. 기존 호스트 키를 검증하는 SSH/SCP로 관리 VM에 전달한다.
3. `/opt/eolwatch`에 소스를 반영하고 그 디렉터리에서 `sudo docker compose up --build -d`를 실행한다.
4. `status.sh`와 브라우저에서 기동·기존 분석 이력을 확인한다.

기존 `.env`, SSH 키·known_hosts, PostgreSQL·분석 원본·DB 캐시 볼륨을 유지한다. 코드 갱신에 seed 실행·볼륨 삭제·DB 초기화는 포함하지 않는다. 백업·복구는 코드 갱신과 별도로 실제 결과를 확인해 기록한다.

## 4. 현재 분석 방식

`작업 대상`에서 서버와 범위를 선택하고 `취약점 분석`을 누른다.

| 선택 | 범위 |
|---|---|
| Ubuntu 설치 패키지 | dpkg 설치 패키지 |
| 데모 앱 · Python | SSH 사용자 홈의 고정 `eolwatch-demo/.venv` 설치 라이브러리 |

Syft 1.51.1은 대상에서 실행하고, 관리 worker가 SPDX 2.3 변환·Grype 0.118.0 분석·저장을 수행한다. 대상 사용자 디렉터리에 검증된 도구와 임시 설정 파일을 배치하되 분석 자체가 OS·앱 패키지를 업데이트하지는 않는다. 기존 `SSH 점검`은 자원 상태 수집과 자체 SPDX 생성의 별도 기능이다.

현재 저장된 전후 결과를 조회하는 데 추가 업데이트·분석은 필요하지 않다. 실제 갱신을 다시 재현해야 하면 [조치 시연 안내](../../docs/REMEDIATION_DEMO.md)의 baseline → 웹 분석 → fixed → 웹 재분석을 따른다. 재실행한 작업·분석 ID와 취약점 DB 기준은 다시 기록한다. 결과가 0건이어도 수동 VEX를 자동 `FIXED`로 바꾸지 않는다.

## 5. 장애와 보관

- 웹 접속 문제는 `status.sh`의 VM 상태와 JSON `/health` 결과부터 확인한다.
- 분석 실패는 작업 이력의 실패 코드·메시지를 확인한다. `.venv` 없음·SSH 인증·호스트 키·아키텍처·도구 검증·시간 초과는 정상 0건과 구분한다.
- `analysis_artifacts`는 worker의 `/var/lib/eolwatch/analysis`, `analysis_cache`는 `/var/cache/eolwatch`에 연결된다.
- 제출·설명에 사용할 저장 자료는 `reports/`의 원본·화면·비교 PDF·JSON이다. 실시간 시연을 못 하면 이 자료가 이전에 검증한 기록임을 밝히고 사용한다.
- Black Duck 호환 SPDX 샘플은 선택적 반입 예제다. 현재 실행 경로를 Black Duck 분석이라고 설명하지 않는다.
