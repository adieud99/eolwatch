# SBOM 생성·취약점 분석 도구 연동

현재 기본 사용 흐름은 웹에서 분석을 요청하는 방식이다. [웹 분석 실행](WEB_ANALYSIS.md), [실제 웹 시연 검증 기록](archive/WEB_ANALYSIS_VERIFICATION_2026-09-15.md), [데모 앱 업데이트 전후 비교](REMEDIATION_DEMO.md)를 참고한다. 아래 맥 스크립트는 수동 OS 분석·결과 반입 경로로 유지한다.

## 역할과 첫 시연 범위

- Syft: 대상 VM의 설치된 Ubuntu OS 패키지를 식별한다.
- SPDX 2.3: EOLWatch에 저장하는 교환 형식이며 Grype의 실제 분석 입력이다.
- Grype: 해당 SPDX의 구성요소를 취약점 DB와 대조한다.
- EOLWatch: SBOM·분석 보고서 원본을 보관하고 CVE를 서버 및 구성요소와 연결한다.

첫 자동화 대상은 `LAB-VM-01`, `LAB-VM-02`다. `dpkg-db-cataloger`로 Ubuntu의 설치 패키지를 수집한다. 프로젝트 소스의 모든 의존성·펌웨어·커널 실행 상태까지 분석했다는 의미는 아니다. Black Duck 계정은 필요하지 않다.

## 도구 준비

프로젝트 루트에서 다음 명령으로 도구를 설치한다.

```bash
python3 scripts/install-analysis-tools.py
```

고정 버전은 Syft 1.51.1, Grype 0.118.0이다. GitHub 공식 릴리스의 체크섬과 다운로드한 아카이브의 SHA-256을 비교한 다음 바이너리만 추출한다. 설치 위치는 Git에서 제외되는 `infrastructure/local-vm/runtime/tools`다. 전역 프로그램을 교체하지 않는다.

도구의 역할과 옵션은 [Syft CLI](https://oss.anchore.com/docs/reference/syft/cli/), [SBOM 출력 형식](https://oss.anchore.com/docs/guides/sbom/formats/), [Grype SBOM 분석](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/)을 참고한다.

## 실제 VM 분석 실행

```bash
python3 scripts/analyze-lab.py --asset-tag LAB-VM-01
```

대화형 실행에서는 업로드할 때 관리자 비밀번호를 입력한다. 자동 실행은 `EOLWATCH_USERNAME`, `EOLWATCH_PASSWORD` 환경변수를 사용한다. 기본 API 주소는 VM 서비스인 `http://127.0.0.1:18080`이다.

결과 파일만 만들려면 `--no-upload`를 사용한다. 업로드를 다시 시도하려면 다음처럼 기존 실행 폴더를 지정한다.

```bash
python3 scripts/analyze-lab.py --asset-tag LAB-VM-01 --upload-existing-dir infrastructure/local-vm/runtime/analyses/실행폴더
```

- 등록된 자산 태그와 내부 IP가 지정 대상과 일치할 때만 업로드한다.
- 이미 신뢰하는 controller의 대상 호스트 키를 읽어 전달 포트의 SSH 키를 검증한다.
- 대상 VM에는 전용 사용자 디렉터리의 Syft 바이너리와 설정 파일을 설치한다. OS 패키지를 변경하지 않는다.
- OS 패키지 수집은 대상 VM에서, SPDX 변환과 Grype 분석은 스크립트를 실행하는 맥에서 수행한다.
- Syft의 실제 Ubuntu 배포판 정보를 Grype에 전달해 배포판별 취약점 매칭에 사용한다.
- 각 실행 폴더에 명령·종료 코드·시각·경고·파일 해시, Syft JSON, SPDX JSON, Grype JSON, 가져오기 묶음을 보관한다. 실패·업로드 재시도도 별도 기록한다.
- 대상 2대의 실행 옵션은 준비했지만 이번 연동의 실제 Grype 분석은 LAB-VM-01에서 검증했다.

## 저장 API

관리자 Bearer 토큰으로 `POST /api/analyses/import`를 호출한다.

```json
{
  "asset_id": 1,
  "scan_scope": "ubuntu-dpkg-installed",
  "sbom": {"spdxVersion": "SPDX-2.3"},
  "report": {"descriptor": {"name": "grype", "version": "0.118.0"}}
}
```

위 JSON은 필드 구조를 보여주는 축약 예시다. 실제 요청에는 유효한 SPDX 전체 문서와 Grype 전체 JSON 보고서가 필요하다. 보고서의 `matches`는 필수이며, 빈 배열은 유효한 0건 분석으로 구분한다.

- `GET /api/analyses`: 최근 가져오기 이력 최대 100건
- `GET /api/analyses/{id}/bundle`: 저장된 SBOM·Grype 원본 묶음
- `GET /api/vulnerabilities?sbom_id={id}`: 해당 SBOM에 연결된 CVE 및 조치 상태

## 화면

분석 묶음 JSON을 가져오는 화면은 2026-09-18 재범위화에서 제거했다. 반입은 위 `POST /api/analyses/import` API와 `analyze-lab.py` 스크립트로만 수행한다. 반입한 결과는 `검사 기록` → `검사 이력`에서 도구 버전, 검사 범위, 구성요소 및 CVE 수를 확인하고 원본을 내려받을 수 있다. CVE 목록은 `CVE 결과·조치`에서 선택한 SBOM에 한정해 확인한다. OSV 교차 검증은 별도 API로 유지한다.

## 데이터 처리 원칙

- 공식 SPDX 스키마 검증과 Grype 필수 필드 검증을 거친다.
- Grype의 purl·이름·버전을 해당 SBOM 구성요소와 대조한다. purl이 없으면 이름·버전이 유일하게 일치할 때만 연결한다.
- Grype 보고서의 원본 유형은 SPDX 입력이어도 `directory`로 남을 수 있다. 실제 입력 파일은 실행 기록과 해시로 확인한다.
- 구성요소가 맞지 않으면 요청 전체를 롤백한다. SBOM만 남는 부분 저장을 방지한다.
- 같은 자산·SBOM·보고서 묶음을 다시 가져오면 기존 이력을 반환한다.
- 같은 SBOM namespace를 다른 자산이나 다른 원본에 재사용하면 충돌로 처리한다.
- CVE 식별자 또는 관련 CVE 별칭을 가진 분석 행을 관리한다. CVE가 없는 분석 행도 원본에 보관하고 제외 건수를 표시한다.
- 구성요소별 심각도·분석 출처·수정 버전 목록을 저장한다. 여러 수정 계열을 임의로 하나의 권장 버전으로 선택하지 않는다.
- 분석 이력에는 원본 보고서, 도구 버전, 보고서의 DB 정보, SBOM 해시와 묶음 중복 판별 해시를 저장한다. 원본의 `ignoredMatches`도 그대로 보관한다.
- 파일 소유관계는 SPDX 원본에 보관하고 검색용 의존관계에는 패키지 간 연결만 저장한다.
- 실제 약 94 MB 묶음에 맞춰 Nginx 요청 크기 한도를 200 MB로 설정했다. 목록 조회는 큰 원본 필드를 제외하며 CVE 화면은 100행씩 표시한다.

## 후속 정확성·조치 검증

현재 연동은 도구의 판정을 수집·저장하는 단계다. 업로드된 보고서의 생성 사실 자체를 암호학적으로 인증하지 않으며, 실제 실행의 근거는 실행 스크립트의 기록과 원본 아티팩트다. 취약점 DB의 제공 범위와 패키지 식별 정확성에 따라 결과가 달라질 수 있다.

재분석에서 누락된 CVE를 자동으로 조치 완료로 바꾸지 않는다. 업데이트 전후 비교는 각 분석의 원본 SBOM과 보고서로 탐지 변화를 보여주며, 조치 상태는 수동으로 관리한다. 동일 SBOM에 분석을 다시 가져오면 발견된 구성요소의 표시 정보는 최신 가져오기 결과로 갱신하고, 과거 분석 원본은 분석 이력에 유지한다. 개요의 `open_cves`는 기존 SBOM 이력을 포함하므로 현재 설치 상태만의 집계로 해석하지 않는다. 현재 기준은 `current_open_cves`로 따로 계산한다.
