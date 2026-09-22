# 취약점 스캐너 선택과 업데이트 검토 (2026-09-22)

> 2026-09-22 저녁 반영: Trivy 0.74.0을 worker 이미지에 함께 설치해 같은 SPDX를 2차로 검사하고, 검사 결과에 "두 도구 일치 / Grype만 / Trivy만"을 표시한다(`analysis_executor._secondary_tool`, `_summarize_trivy`, `analysis.py`의 `secondary`). 아래 비교와 절차는 그 결정의 근거다.

교수님 질문 "Grype 말고 다른 걸 쓰거나 같이 쓰거나, 업데이트가 있는지 확인해라"에 대한 조사 기록이다. 결론은 **Grype를 1차 스캐너로 유지하고, Trivy를 같은 SPDX 파일에 대한 선택적 2차 스캐너로 붙이며, Grype DB 빌드 시각과 갱신 가능 여부를 화면에 표시한다**이다. 조사 시점은 2026-09-22이며 모든 수치와 URL은 이 날짜 기준이다.

## 1. 현재 고정 버전과 최신 릴리스

EOLWatch는 `backend/tools/install_anchore.py`에서 Syft 1.51.1, Grype 0.118.0을 SHA-256으로 고정해 워커 이미지에 설치한다. GitHub 릴리스 API(`/repos/anchore/{syft,grype}/releases/latest`)로 확인한 결과 두 도구 모두 새 버전이 있다.

| 도구 | 고정 버전 | 최신 버전 | 최신 릴리스 일시(UTC) | 판정 |
|---|---|---|---|---|
| Syft | 1.51.1 (2026-08-27) | **1.52.0** | 2026-09-17 14:38 | 새 버전 있음 |
| Grype | 0.118.0 (2026-08-27) | **0.119.0** | 2026-09-17 16:45 | 새 버전 있음 |

### 1-1. 최신 릴리스 아카이브 SHA-256

`syft_1.52.0_checksums.txt`, `grype_0.119.0_checksums.txt`(각 릴리스의 자산)에서 그대로 옮긴 값이다. `install_anchore.py`의 `VERSIONS`와 `CHECKSUMS`를 교체할 때 사용한다.

| 아카이브 | SHA-256 |
|---|---|
| `syft_1.52.0_linux_amd64.tar.gz` | `caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d` |
| `syft_1.52.0_linux_arm64.tar.gz` | `c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706` |
| `grype_0.119.0_linux_amd64.tar.gz` | `3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b` |
| `grype_0.119.0_linux_arm64.tar.gz` | `29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8` |

체크섬 파일 주소:

- <https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_checksums.txt>
- <https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_checksums.txt>

### 1-2. 고정 버전과 최신 사이의 변경 요약 (매칭·DB 관련만)

Grype 0.118.0 → 0.119.0 (<https://github.com/anchore/grype/releases/tag/v0.119.0>):

- 배포판 수정 버전(distro fixed version) 때문에 탈락한 매치를 `ignoredMatches`로 내보내 `--show-suppressed`로 볼 수 있게 했다(#3450, #3705). EOLWatch가 "백포트 때문에 제외된 CVE"를 설명하는 근거로 쓸 수 있다.
- `--by-cve` 병합 때 어떤 advisory 레코드가 남는지 실행마다 달라지던 문제를 고쳤다(#3630). EOLWatch는 `--by-cve`를 쓰므로 같은 SBOM을 두 번 검사했을 때 결과가 흔들리던 원인이 사라진다.
- 내부 Syft 라이브러리를 1.52.0으로 올렸고 grpc, x/crypto 등 의존성 취약점 6건을 해소했다.

Syft 1.51.1 → 1.52.0 (<https://github.com/anchore/syft/releases/tag/v1.52.0>):

- `.deb` 아카이브 압축 해제 크기와 압축된 커널 모듈 확장 크기에 상한을 두었다(#5293, #5294). 대상 서버에서 실행하는 Syft의 메모리 폭주 방지에 해당한다.
- syft-json 입력을 그대로 통과시키는 `passthrough-exact-format` 옵션이 추가되었다. 현재 흐름(syft-json → `syft convert` → SPDX 2.3)에는 영향이 없다.
- 의존성 취약점 6건 해소(Grype와 동일 목록).

두 릴리스 모두 dpkg 매칭 규칙이나 SPDX 2.3 출력 형식의 변경은 없다. 따라서 버전을 올려도 EOLWatch의 검증 로직(`pkg:deb` PURL 비율 검사, `descriptor.name == grype` 검사)은 그대로 통한다.

### 1-3. 실행 파일 버전과 취약점 DB는 별개다

Grype는 실행 파일과 취약점 DB를 따로 갱신한다. 설정 기본값은 다음과 같다(<https://oss.anchore.com/docs/reference/grype/configuration/>).

- `db.auto-update: true`: 실행할 때마다 `https://grype.anchore.io/databases`에서 새 DB가 있는지 확인하고 받는다.
- `db.max-allowed-built-age: 120h`, `db.validate-age: true`: DB 빌드가 5일보다 오래되면 검사를 거부한다.
- `db.require-update-check: false`: 갱신 확인에 실패해도(오프라인) 캐시된 DB로 검사한다.

`analysis_executor.py`의 `_environment()`는 `GRYPE_DB_CACHE_DIR`만 지정하므로 워커는 기본값대로 검사마다 DB를 자동 갱신한다. 실제 검사 결과 `descriptor.db.status.built`에 빌드 시각이 남고(예: 2026-09-15 실행분은 `2026-09-15T06:31:36Z`), 이 값이 `database_info`로 저장되어 검사 이력 화면에 "DB 기준"으로 표시된다. 2026-09-22 커널 CVE 검증에서 확인한 libexpat1 불일치 2건도 DB 빌드(06:39 UTC)와 Ubuntu 수정 공개(13:50 UTC) 사이의 시차였다([KERNEL_CVE_VERIFICATION_2026-09-22.md](KERNEL_CVE_VERIFICATION_2026-09-22.md)). 즉 "업데이트가 있는지"는 실행 파일 버전보다 **DB 빌드 시각**이 더 자주, 더 크게 결과를 바꾼다.

## 2. 대안 비교

비교 기준은 EOLWatch의 실제 작업, 즉 **Ubuntu dpkg 설치 패키지의 SPDX 2.3 SBOM을 배포판 데이터와 대조하는 일**이다.

| 항목 | Grype 0.119.0 | Trivy 0.74.0 | OSV-Scanner 2.6.0 | Ubuntu `pro` 도구 | CISA KEV | FIRST EPSS |
|---|---|---|---|---|---|---|
| 성격 | 스캐너 | 스캐너 | 스캐너 | 대상 서버에서 실행하는 점검 명령 | 우선순위 데이터 | 우선순위 데이터 |
| 라이선스 | Apache-2.0 | Apache-2.0 | Apache-2.0 | 클라이언트는 GPL-3.0, 데이터는 Canonical | CC0 1.0 | 무료 공개 API, 인증 불필요 |
| SBOM 입력 | `sbom:경로`, SPDX·CycloneDX·syft-json | `trivy sbom 파일`, SPDX(JSON·tag-value)·CycloneDX JSON | 파일명 패턴(`*.spdx.json`, `*.cdx.json`)으로 자동 인식, PURL 기반 | 없음(서버의 apt 상태를 직접 읽음) | 해당 없음 | 해당 없음 |
| Ubuntu 데이터 출처 | Ubuntu CVE tracker 기반 grype-db | Ubuntu 보안 권고(Ubuntu CVE Tracker), Ubuntu priority를 심각도로 사용 | OSV.dev의 `Ubuntu` 생태계(`canonical/ubuntu-security-notices` OSV 내보내기, CC-BY-SA 4.0) | Ubuntu 보안팀 데이터 그 자체 | 미국 CISA | FIRST |
| 미수정 CVE 기본 보고 | 보고함(`--only-fixed`로 제외) | 보고함(`--ignore-unfixed`로 제외) | 보고함(`UBUNTU-CVE-*` 레코드에 `introduced: 0`만 있고 `fixed` 없음) | `pro fix`가 "수정판 없음"을 알려 줌 | 해당 없음 | 해당 없음 |
| EPSS·KEV | JSON에 `epss`·`knownExploited`·`risk` 포함, `--sort-by risk` 기본 | 없음(Discussion #10840, 2026-06-12, 유지보수자 응답 없음) | 없음 | 없음 | KEV 자체 | EPSS 자체 |
| EOLWatch 적합성 | 현재 1차 스캐너. 백포트 인식 dpkg 매칭, 80건 표본 검증 완료 | Grype와 병행해 두 결과의 교집합·차집합을 보여 주는 2차 의견 | Ubuntu 데이터가 별도 계보(OSV)라 3차 의견 후보. 다만 `pkg:deb` SBOM 처리 범위가 문서에 명시되지 않음 | 스캐너 결과의 정답지. CVE별 확인 API로 이미 사용 중 | Grype가 이미 내장. 별도 연동 불필요 | Grype가 이미 내장. 별도 연동 불필요 |

### 2-1. Trivy (Aqua Security)

- 최신 0.74.0(2026-08-14), Apache-2.0. 문서: <https://trivy.dev/latest/docs/target/sbom/>, <https://trivy.dev/latest/docs/coverage/os/ubuntu/>, <https://trivy.dev/latest/docs/scanner/vulnerability/>, <https://trivy.dev/latest/docs/configuration/db/>.
- SBOM 입력은 `trivy sbom /path/to/sbom_file`이며 형식을 자동 인식한다. Ubuntu는 Ubuntu 자체 보안 권고를 쓰고, 심각도는 NVD보다 Ubuntu priority를 우선한다(예: CVE-2019-15052는 NVD Critical, Ubuntu Medium이면 Medium으로 표시). 수정 버전은 Ubuntu 패치 버전이다. 미수정 CVE는 기본으로 보고하며 `--ignore-unfixed`로 숨긴다. 이 점은 Grype와 같다.
- 주의 1: 문서가 "다른 도구가 만든 SBOM은 Trivy 고유 속성이 없어 부정확할 수 있다"고 명시한다. Discussion #7850(<https://github.com/aquasecurity/trivy/discussions/7850>, 2024-11)에서 유지보수자는 Syft가 소스 패키지 이름을 PURL `upstream` 한정자에 넣는데 Trivy는 이를 읽지 않아 바이너리 패키지 이름으로 매칭한다고 설명했다. Ubuntu CVE 데이터도 소스 패키지 기준이므로 `libexpat1`(소스 `expat`) 같은 항목이 Trivy에서는 빠질 수 있다. 따라서 Trivy를 붙일 때는 먼저 저장된 `sbom.spdx.json` 하나로 Grype 결과와 대조해 "Trivy만 놓친 것"이 무엇인지 확인해야 한다. 이 차이 자체가 2차 의견 화면의 설명 거리가 된다.
- 주의 2: EPSS·KEV를 제공하지 않는다(<https://github.com/aquasecurity/trivy/discussions/10840>). 우선순위 정보는 Grype 쪽 값을 그대로 쓴다.
- DB는 `ghcr.io/aquasecurity/trivy-db` 등 OCI 레지스트리에서 받으며 `--skip-db-update`, `--download-db-only`로 제어한다. 워커에 외부 접근이 필요한 점은 Grype와 같다.

### 2-2. OSV-Scanner (Google)

- 최신 2.6.0(2026-09-14), Apache-2.0. 문서: <https://google.github.io/osv-scanner/usage/scan-source>, <https://google.github.io/osv-scanner/supported-languages-and-lockfiles/>, 데이터 출처: <https://google.github.io/osv.dev/data/>.
- SBOM은 파일명 패턴(`*.spdx.json`, `bom.json`, `*.cdx.json` 등)으로 인식하고 PURL로 조회한다. Ubuntu 데이터는 Canonical이 OSV 형식으로 내보내는 `UBUNTU-CVE-*` 레코드이며, OSV API(`POST https://api.osv.dev/v1/query`, ecosystem `Ubuntu:24.04:LTS`)로 직접 확인했다. `expat 2.6.1-2ubuntu0.4`(noble)는 CVE-2026-50219·45186을 포함한 26건을 돌려주었다. 수정판이 없는 CVE도 `introduced: 0`만 있고 `fixed`가 없는 레코드로 들어 있다(같은 응답의 cadaver·tdom·wbxml2 항목). 다만 빠진 것도 있다. 커널 CVE-2026-80699 레코드는 24.04의 `linux-aws-6.14` 등 38개 항목만 있고 25.10 항목이 없어, `linux-aws 7.0.0-1012.12`(Ubuntu:25.10) 조회 2,177건에는 CVE-2026-80699·80796·89802가 나오지 않았다. Ubuntu 추적기는 셋 다 resolute `needed`이고 Grype도 보고한다. 즉 OSV 경로는 Grype보다 미수정 커널 CVE를 적게 낸다.
- 한계: 결과 ID가 `UBUNTU-CVE-*`이고 `aliases`가 비어 있어 CVE ID로 합치려면 접두사를 벗겨야 한다. Grype의 `--by-cve`에 해당하는 옵션이 없다. 문서는 SBOM에서 어떤 PURL 유형을 처리하는지 명시하지 않고, Ubuntu 패키지의 문서화된 경로는 컨테이너 이미지의 `/var/lib/dpkg/status` 읽기다. 그리고 OSV 레코드도 시차가 있다. 2026-09-22 조회에서 `UBUNTU-CVE-2026-50219`의 resolute(25.10) 항목은 `fixed` 없이 `introduced: 0`만 있었는데 Ubuntu 추적기는 전날 2.7.4-1ubuntu0.1로 released였다. EPSS·KEV는 없다.
- 적합성: CLI를 붙이기보다 **OSV API를 CVE·패키지 단위 교차 확인 소스**로 쓰는 편이 EOLWatch 구조에 맞는다. 다만 Ubuntu 공식 API(아래)가 같은 역할을 더 정확히 하므로 우선순위는 낮다.

### 2-3. Ubuntu 자체 도구: `pro`, `ubuntu-security-status`, Ubuntu Security API

- `pro fix --dry-run CVE-xxxx`: 대상 서버에서 해당 CVE가 어떤 설치 패키지에 영향을 주는지, 수정판이 표준 저장소에 있는지, Pro(esm-infra·esm-apps)가 필요한지 보여 준다. 표준 저장소 수정은 구독 없이 동작한다. 문서: <https://ubuntu.com/pro-client/docs/en/latest/howtoguides/fix_how_to_resolve_given_cve/>, <https://ubuntu.com/pro-client/docs/en/latest/howtoguides/fix_how_to_know_what_the_fix_command_would_change/>.
- `pro security-status`(구 `ubuntu-security-status`): main/universe/서드파티/설치 소스 없음 패키지 수와 보류 중인 보안 업데이트 수, ESM 적용 범위를 보여 준다. CVE 목록은 내지 않는다. 구독이 없어도 실행된다. 문서: <https://ubuntu.com/pro-client/docs/en/latest/explanations/how_to_interpret_the_security_status_command/>.
- Ubuntu Security API: `https://ubuntu.com/security/cves/CVE-2026-50219.json`처럼 CVE별 JSON을 주며 `priority`와 릴리스별 `status`·수정 버전을 담는다(직접 조회로 확인: resolute released 2.7.4-1ubuntu0.1). 상태 값과 우선순위 정의는 <https://ubuntu.com/security/cves/about>에 있다. 2026-09-22 표본 80건 대조에 쓴 것이 이 데이터다.
- 적합성: 스캐너를 대체하지 않는다. SBOM을 입력받지 않고 서버에서 직접 실행하거나 CVE 하나씩 조회하는 방식이다. EOLWatch에서는 **스캐너 결과의 정답지**로 쓴다. 예를 들어 "수정판 있음" CVE의 `fixed_version`을 Ubuntu API의 release 버전과 자동 대조하는 검증 열을 붙일 수 있다.

### 2-4. CISA KEV와 FIRST EPSS

- KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>. JSON 피드 `/sites/default/files/feeds/known_exploited_vulnerabilities.json`, 라이선스 CC0 1.0(`/sites/default/files/licenses/kev/license.txt`). 2026-09-21 카탈로그 버전 2026.09.21, 1,717건.
- EPSS: <https://www.first.org/epss/>, API `https://api.first.org/data/v1/epss?cve=CVE-...`(<https://api.first.org/epss/>). 인증 없이 조회되며 `epss`(30일 내 악용 확률)·`percentile`·`date`를 준다. 직접 조회 확인: CVE-2021-44228은 epss 0.99999, percentile 1.0.
- Grype는 둘 다 DB에 내장한다(<https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/>). JSON의 `vulnerability.epss[]`, `vulnerability.knownExploited[]`, `vulnerability.risk`가 그것이고 `risk`는 EPSS와 CVSS를 결합해 0~10으로 만든 값이며 KEV 등재 시 최대 위협으로 올린다. 저장된 2026-09-15 LAB-VM-01 검사(12,241 매치)를 확인하면 12,194건에 `epss`가, 4건에 `knownExploited`(CVE-2026-53362)가 이미 들어 있다. 커밋된 코드(3f6a17e 기준)는 이 필드를 저장하지 않았고, 2026-09-22 작업 트리에서 `component_vulnerabilities.epss·epss_percentile·kev·risk` 열(마이그레이션 `a9c4e1f7b3d2`)과 검사별 `kev_cve_count`·`epss_cve_count` 집계가 추가되는 중이다. 별도 피드를 연동할 필요 없이 Grype JSON에서 읽어 오는 방식이다.

## 3. 권고

### 3-1. Grype를 1차 스캐너로 유지한다

- 백포트를 인식하는 dpkg 매칭을 이미 쓰고 있다. `GRYPE_CONFIG`로 CPE 매칭을 끄고 `--distro ubuntu:<버전>`을 넘겨 Ubuntu 수정 버전 기준으로만 판정한다. 2026-09-22에 무작위 80건을 Ubuntu 추적기와 대조해 78건이 상태·수정 버전까지 일치했고 불일치 2건은 DB 시차였다.
- EPSS·KEV·risk가 JSON에 이미 있어 우선순위 지표를 추가 연동 없이 얻는다. Trivy와 OSV-Scanner는 둘 다 없다.
- `--by-cve`, `--only-fixed`, `--show-suppressed`(0.119.0부터 배포판 수정 버전으로 탈락한 매치도 노출) 등 EOLWatch 설명 화면에 필요한 옵션이 갖춰져 있다.
- 실행 파일·DB 검증 경로(체크섬 고정, `manifest.json`, `descriptor.db.status.built` 저장, 전후 비교에서 DB 기준 시각 차이 경고)가 이미 구현되어 있다.

### 3-2. Trivy를 같은 SPDX에 대한 선택적 2차 스캐너로 붙인다

`analysis_executor.py`의 현재 흐름은 `syft convert → sbom.spdx.json → grype sbom:<spdx> --config grype.yaml --distro ubuntu:<ver> --by-cve -o json → grype.json`이다. 2차 스캐너는 **같은 `spdx_path`**를 입력으로 Grype 직후에 한 단계 더 실행하면 된다.

1. 설치: `install_anchore.py`와 같은 방식으로 `trivy_<ver>_Linux-64bit.tar.gz`·`Linux-ARM64.tar.gz`를 `trivy_<ver>_checksums.txt`의 SHA-256으로 고정해 `/opt/analysis-tools/trivy`에 넣고 `manifest.json["tools"]["trivy"]`에 기록한다. `_tools()`에서 `settings.analysis_trivy_path`가 비어 있으면 건너뛰도록 해 기존 배포에 영향이 없게 한다.
2. 환경: `_environment()`에 `TRIVY_CACHE_DIR=<cache>/trivy`, `TRIVY_NO_PROGRESS=true`를 추가한다. Grype처럼 검사 시 DB를 받는다.
3. 실행: `report_path = run.local("grype-scan", ...)` 다음에
   `run.local("trivy-scan", [trivy, "sbom", str(spdx_path), "--scanners", "vuln", "--format", "json", "--output", str(run.directory / "trivy.json")], settings.analysis_scan_timeout_seconds, env)`
   를 넣는다. 버전 기록은 `syft-version`·`grype-version`과 같은 자리에서 `trivy version -f json`으로 남긴다. 실패는 `TOOL_FAILED`로 검사 전체를 막지 말고 `run.manifest["secondary_scan"] = {"status": "failed", ...}`로 기록만 한다. 2차 의견이 1차 결과 저장을 막으면 안 된다.
4. 저장: `result["secondary_report"] = trivy_json`을 반환하고 `analysis.py`의 반입 트랜잭션에서 검사 실행(run)에 딸린 원본 묶음으로 보관한다. `Vulnerability` 행에는 섞지 않는다. 기록 근거는 계속 Grype 하나다.
5. 비교 화면(검사 결과의 "2차 의견" 탭): Trivy JSON의 `Results[].Vulnerabilities[]`에서 `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`를 뽑아 Grype의 `matches[].vulnerability.id`, `artifact.name`, `artifact.version`, `fix.versions`와 (CVE, 패키지 이름) 키로 맞춘다. 표시 항목은 다음 네 가지다.
   - 교집합: 두 도구가 같은 CVE·패키지를 냈고 수정 버전도 같음. 신뢰도 높음.
   - Grype만: Trivy가 놓친 항목. 앞서 본 소스 패키지 이름 문제(`libexpat1` vs `expat`)가 여기서 드러날 가능성이 크다.
   - Trivy만: Grype DB 시차 또는 매칭 규칙 차이. Ubuntu API로 확인할 후보다.
   - 수정 버전 불일치: 같은 CVE인데 두 도구의 `FixedVersion`이 다른 경우.
   숫자 4개와 상세 표를 보여 주고, 각 행에 Ubuntu Security API 링크(`https://ubuntu.com/security/CVE-...`)를 붙인다.

### 3-3. Grype DB 빌드 시각과 갱신 가능 여부를 화면에 표시한다

- 이미 있는 것: `descriptor.db.status.built`가 `database_info`에 저장되고 검사 이력에 "DB 기준"으로 표시된다. 전후 비교는 DB 기준 시각이 다르면 경고한다.
- 추가할 것 1: 검사 직전에 `grype db check -o json`을 `run.local("grype-db-check", ...)`로 실행해 갱신 가능 여부와 현재·최신 DB 빌드 시각을 `run.manifest["grype_db_check"]`와 `database_info`에 남긴다. `db check`는 "Check to see if there is a database update available"이다(<https://oss.anchore.com/docs/reference/grype/cli/>). 자동 갱신이 실패한 채 캐시 DB로 검사한 경우를 구분하는 것이 목적이다.
- 추가할 것 2: 검사 이력과 검사 결과 상단에 "DB 기준 2026-09-21 06:39 UTC (N일 전)" 배지를 두고, 빌드 후 24시간이 넘었으면 "새 DB로 재검사 권장", 120시간(Grype `max-allowed-built-age` 기본)이 넘었으면 경고색으로 표시한다.
- 추가할 것 3: 실행 파일 버전은 GitHub 릴리스 API를 관리 서버가 하루 한 번 조회해 "고정 버전 0.118.0, 최신 0.119.0(2026-09-17)"을 설정 화면에 보여 준다. 워커 이미지 재빌드는 사람이 결정한다(4장).
- 같이 하면 좋은 것: Grype JSON의 `epss`·`knownExploited`·`risk`를 `Vulnerability` 행에 저장하고 CVE 표에 "EPSS %", "KEV" 열을 추가한다. 데이터는 이미 있고 파싱만 남았다.

## 4. 업데이트 확인 절차

1. 최신 버전 확인
   ```bash
   curl -s https://api.github.com/repos/anchore/syft/releases/latest  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["tag_name"],d["published_at"])'
   curl -s https://api.github.com/repos/anchore/grype/releases/latest | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["tag_name"],d["published_at"])'
   ```
2. 체크섬 파일을 받아 `linux_amd64`·`linux_arm64` 네 값을 확인한다.
   ```bash
   curl -sL https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_checksums.txt   | grep -E 'linux_(amd64|arm64)\.tar\.gz'
   curl -sL https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_checksums.txt | grep -E 'linux_(amd64|arm64)\.tar\.gz'
   ```
3. `backend/tools/install_anchore.py`의 `VERSIONS`와 `CHECKSUMS` 네 항목을 1-1의 값으로 바꾼다. Syft는 워커용 1개와 대상 서버 복사용 amd64·arm64 2개가 모두 같은 체크섬 표를 쓰므로 표만 맞으면 된다.
4. 워커 이미지를 다시 만든다. 설치 단계에서 체크섬이 다르면 빌드가 실패한다.
   ```bash
   docker compose build worker
   docker compose up -d worker
   ```
5. 같은 서버를 다시 검사하고 검사 이력에서 도구 버전(`scanner_version`)과 "DB 기준"이 바뀌었는지 본다.
6. `검사 전후 비교`에서 직전 검사를 "이전", 새 검사를 "이후"로 선택해 계속 검출·새로 검출·재분석 미검출 수를 본다. 도구 버전이 다르면 비교 화면이 주의사항을 붙이므로, 차이가 난 CVE는 Ubuntu Security API로 확인해 도구 변경 때문인지 DB 갱신 때문인지 기록한다([COMPARISON_REPORTS.md](COMPARISON_REPORTS.md)).
7. `docs/ANALYSIS_TOOLS.md`의 고정 버전 문구와 이 문서의 1장을 갱신한다.

## 5. 참고 URL

- GitHub 릴리스 API: <https://api.github.com/repos/anchore/syft/releases/latest>, <https://api.github.com/repos/anchore/grype/releases/latest>
- Grype 릴리스 노트: <https://github.com/anchore/grype/releases/tag/v0.119.0>, <https://github.com/anchore/grype/releases/tag/v0.118.0>
- Syft 릴리스 노트: <https://github.com/anchore/syft/releases/tag/v1.52.0>, <https://github.com/anchore/syft/releases/tag/v1.51.1>
- Grype 문서: <https://oss.anchore.com/docs/reference/grype/cli/>, <https://oss.anchore.com/docs/reference/grype/configuration/>, <https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/>
- Trivy 문서: <https://trivy.dev/latest/docs/target/sbom/>, <https://trivy.dev/latest/docs/coverage/os/ubuntu/>, <https://trivy.dev/latest/docs/scanner/vulnerability/>, <https://trivy.dev/latest/docs/configuration/db/>, <https://github.com/aquasecurity/trivy/discussions/7850>, <https://github.com/aquasecurity/trivy/discussions/10840>
- OSV: <https://google.github.io/osv-scanner/usage/scan-source>, <https://google.github.io/osv-scanner/supported-languages-and-lockfiles/>, <https://google.github.io/osv.dev/data/>, <https://api.osv.dev/v1/query>
- Ubuntu: <https://ubuntu.com/security/cves/about>, <https://ubuntu.com/security/cves/CVE-2026-50219.json>, <https://ubuntu.com/pro-client/docs/en/latest/howtoguides/fix_how_to_resolve_given_cve/>, <https://ubuntu.com/pro-client/docs/en/latest/explanations/how_to_interpret_the_security_status_command/>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>, <https://www.cisa.gov/sites/default/files/licenses/kev/license.txt>
- FIRST EPSS: <https://www.first.org/epss/>, <https://api.first.org/epss/>
