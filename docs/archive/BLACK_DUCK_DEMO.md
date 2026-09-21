# Black Duck 연동 시연 절차

> **보관 문서.** Black Duck을 주 분석 경로로 쓰던 시기의 절차다. 현재 시연은 Syft·Grype만 사용하며 Black Duck 계정·서버가 필요 없다. 여기 나오는 `scripts/blackduck-scan.sh`는 제거했으므로, 다시 쓰려면 Detect 실행 명령을 새로 작성해야 한다. SPDX 2.3 호환 샘플 `samples/spdx-2.3-blackduck-compatible.json`은 백엔드 테스트가 사용하므로 그대로 둔다.

## 준비물

- 사용할 수 있는 Black Duck SCA 서버 주소
- 해당 서버에서 발급한 API 토큰
- Black Duck 공식 배포처에서 받은 Detect JAR
- Java 17 이상

Black Duck 서버나 라이선스가 없으면 실제 Black Duck 분석은 실행할 수 없다. Detect 저장소가 Apache-2.0으로 공개되어 있어도 분석 결과를 만드는 Black Duck SCA 서버는 별도 제품이다.

## 1. 분석 실행

토큰은 명령행에 직접 쓰지 않고 현재 셸의 환경변수로 넣는다.

```bash
export BLACKDUCK_URL='https://blackduck.example.com'
export BLACKDUCK_API_TOKEN='발급받은_토큰'
export DETECT_JAR="$HOME/tools/detect.jar"
export BLACKDUCK_PROJECT_NAME='EOLWatch-Demo'
export BLACKDUCK_PROJECT_VERSION='local-vm-1'

./scripts/blackduck-scan.sh ./demo-source
```

## 2. SPDX 내보내기

Black Duck에서 스캔한 프로젝트 버전을 열고 SBOM 보고서에서 SPDX 2.3 JSON을 내려받는다. 제품 버전에 따라 메뉴 이름은 달라질 수 있으므로 실제 학교 계정 화면에서 경로를 확인한다.

## 3. EOLWatch 반영

1. EOLWatch에 관리자로 로그인한다.
2. `SBOM 원장`에서 연결할 VM을 선택한다.
3. Black Duck에서 받은 SPDX JSON을 가져온다.
4. 형식, 구성요소 수, 의존관계 수와 품질 점수를 확인한다.
5. `CVE 조치`에서 해당 SBOM을 선택하고 CVE 조회를 실행한다.
6. 영향 자산, 현재 버전, 조치 버전과 조치 상태를 확인한다.

## 발표할 때 구분해서 말할 내용

- Black Duck: 오픈소스 구성요소를 식별하고 라이선스·취약점 위험을 분석하는 SCA 제품
- Detect: Black Duck에 분석 자료를 보내는 공개 소스 스캔 클라이언트
- SPDX 2.3: Black Duck과 EOLWatch 사이에서 사용하는 표준 SBOM 파일 형식
- OSV: EOLWatch의 독립 시연에서 purl로 취약점 정보를 조회하는 공개 API
