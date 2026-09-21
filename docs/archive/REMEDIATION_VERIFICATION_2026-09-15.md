# 데모 앱 업데이트 전후 실제 검증 — 2026-09-15

## 결과

LAB-VM-01에서 Jinja2 **3.1.4 → 3.1.6**으로 업데이트하고 웹에서 다시 분석했다. 데모 앱 범위의 CVE는 **3건 → 0건**이었다. 같은 서버·같은 범위의 분석 비교에서는 세 CVE 모두 `NO_LONGER_DETECTED`였고 구성요소 제거는 없었다. 업데이트 전후 HTTP 페이지가 정상 출력됐다.

이 결과는 지정된 Python 가상환경의 두 설치 라이브러리에 한정된다. OS 취약점이 모두 해소됐거나 앱 전체에 취약점이 없음을 의미하지 않는다. 과거 CVE 세 건의 수동 VEX는 `AFFECTED`로 유지됐으며 자동으로 `FIXED`를 기록하지 않았다.

## 실제 이력

서비스: `http://127.0.0.1:18080` — 관리 VM의 별도 DB.

| 항목 | 이전 | 이후 |
|---|---|---|
| 자산 | LAB-VM-01 / 자산 #1 / 10.77.0.21 | 동일 |
| 범위 | demo-python-venv | 동일 |
| 작업 | #2 · SUCCESS | #3 · SUCCESS |
| 분석 | #3 | #4 |
| SBOM | #12 | #13 |
| Jinja2 | 3.1.4 | 3.1.6 |
| MarkupSafe | 3.0.3 | 3.0.3 |
| 실제 설치 패키지 | 2개 | 2개 |
| SPDX 구성요소 | 3개(대상 루트 항목 포함) | 3개 |
| CVE / 패키지-CVE 연결 | 3 / 3 | 0 / 0 |
| Syft / Grype | 1.51.1 / 0.118.0 | 동일 |
| Grype DB built | 2026-09-15T06:31:36Z | 동일 |
| 앱 HTTP·렌더링 | 정상 | 정상 |

웹의 `작업 대상`에서 범위를 선택하고 버튼을 클릭해 각각 작업을 생성했다. 브라우저는 각 실행에서 분석 생성 요청을 한 번 보냈다. 수집·SPDX 변환·Grype 실행·결과 저장은 관리 VM의 worker가 수행했다. 수동 JSON 반입이나 맥의 분석 스크립트는 사용하지 않았다. 라이브러리 교체만 `scripts/manage-demo-app.py`로 수행했다.

작업 #2의 실행 시각은 11:26:31–11:26:36 UTC, 작업 #3은 12:59:24–12:59:29 UTC로 저장됐다. 관리 VM의 시계 보정이 중간에 반영됐으므로 두 작업 사이 시각 차이를 실제 작업 소요 시간으로 해석하지 않는다. 각 작업 자체의 실행 시간은 약 5초였다.

## CVE 비교

| CVE | 이전 Grype가 제시한 수정 버전 | 실제 이후 버전 | 비교 |
|---|---|---|---|
| CVE-2024-56201 | 3.1.5 | 3.1.6 | 재분석 미검출 |
| CVE-2024-56326 | 3.1.5 | 3.1.6 | 재분석 미검출 |
| CVE-2025-27516 | 3.1.6 | 3.1.6 | 재분석 미검출 |

`GET /api/analyses/3/compare/4` 결과:

```json
{
  "summary": {
    "persistent": 0,
    "new": 0,
    "no_longer_detected": 3,
    "component_removed": 0
  },
  "warnings": [],
  "comparable": true
}
```

세 행 모두 패키지 식별자 `pkg:pypi/jinja2`, 이전 버전 `["3.1.4"]`, 이후 버전 `["3.1.6"]`이다. 도구·DB 정보가 같고 두 원본 모두 성공한 웹 분석 작업에 연결돼 있다.

## 검증 범위

- 백엔드 **89개 테스트 통과**. 작업·범위 선택·재시도, 실제 설치 수집 범위, 시간 제한, 원본 검증, 같은 자산·범위·순서, 다중 설치 버전, PURL 식별, 수동 상태 유지 등을 확인했다.
- 프런트엔드 **23개 테스트 통과**, 빌드 성공. 범위 전달, 비교 후보 제한, 결과·주의사항 표시, 페이지 이동, 이전 요청 응답 무시를 확인했다.
- 실제 Chrome에서 이전·이후 분석 생성, 작업 완료, 결과 자동 선택을 확인했다. 브라우저 실행 오류 및 실패한 API 요청은 없었다.
- 실제 Chrome에서 분석 #3 → #4를 선택하고 전후 비교 표에 세 CVE와 이전·이후 버전이 표시되는 것을 확인했다. 비교 과정의 쓰기 요청은 로그인뿐이며 CVE 조치 상태 변경은 없었다.
- Mac 개발용 Docker와 관리 VM 모두 최종 코드로 빌드·배포했다. 실제 시연 이력은 관리 VM에 있다.
- 설치 스크립트는 wheel 체크섬 검증, 이전 앱 종료, 가상환경 교체, 정확한 두 패키지 확인, 앱 재시작 및 HTTP 상태 확인을 수행했다. 설치 기록은 대상의 `~/eolwatch-demo/install-manifest.json`에도 저장됐다.

## 원본과 화면

`reports/`와 `infrastructure/local-vm/runtime/`는 Git에서 제외되는 로컬 검증 자료다.

- `reports/demo-baseline-evidence.json`: 이전 작업·분석 메타데이터·SPDX·Grype 원본
- `reports/demo-after-evidence.json`: 이후 작업·분석 메타데이터·SPDX·Grype 원본
- `reports/demo-comparison-evidence.json`: 비교 API 원본
- `reports/demo-baseline-results.png`, `reports/demo-after-results.png`: 각 시점의 CVE 화면
- `reports/demo-app-before.png`, `reports/demo-app-after.png`: 대상 앱의 동일 페이지와 버전 표시
- `reports/demo-analysis-comparison.png`: 웹 전후 비교 화면
- `infrastructure/local-vm/runtime/demo-app/LAB-VM-01/`: 패키지 wheel·공식 체크섬·설치 기록

| 파일 | SHA-256 |
|---|---|
| demo-baseline-evidence.json | e4a83e5bf0b605adb865d6e8eb2d1a15ed8f419ca61b5b2eb61f1deae4e399a2 |
| demo-after-evidence.json | 44730f03187368aadbc2f312e4fdc814958425222d50658bbd43d2e8a658a803 |
| demo-comparison-evidence.json | 9052d2299c1821cbf57db644c338cbc89618bd6453cd2b18b5dbb9ddb925812d |

재현 방법, 전체 구조와 발표 순서: [REMEDIATION_DEMO.md](../REMEDIATION_DEMO.md).
