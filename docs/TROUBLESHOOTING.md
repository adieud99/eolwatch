# 트러블슈팅 — 2026-09-21 실제로 겪은 문제와 해결

실제 서버(srv-han EC2, srv-na 학교 내부망)와 실제 AI 키로 하루 동안 돌리면서 만난 문제를 원인·해결·재발 시 대처 순서로 적는다. 화면에 뜬 문구로 찾으면 된다.

## 1. `SSH_CONNECTION` · "Unable to connect to port 22 on 192.168.217.245"

**원인** 두 가지가 겹쳤다. (a) 192.168.217.245는 학교 내부망 사설 IP라 집·다른 네트워크에서는 PuTTY로도 붙을 수 없다. (b) Mac이 Wi-Fi를 바꾼 뒤 Docker Desktop의 네트워크가 예전 상태로 굳어, Mac에서는 22번이 열리는데 컨테이너에서는 같은 주소가 "연결 거부"였고 인터넷(1.1.1.1)까지 막혀 있었다.

**확인** `ifconfig`로 Mac 주소를 보고 `nc -z -G 3 192.168.217.245 22`로 Mac에서 붙는지 확인한다. Mac은 되는데 홈페이지만 안 되면 (b)다.

**해결** (a) 서버와 같은 네트워크에 붙거나, EOLWatch를 학교 VM에 배포하거나(`docs/DEPLOYMENT.md`), VPN을 쓴다. (b) Docker Desktop을 완전히 종료하고 다시 켠다. `quit`만으로 안 멈추면 `pkill -f com.docker.backend` 뒤 `open -a Docker`.

## 1-1. Mac에서는 붙는데 컨테이너에서만 모든 내부망 장비가 "연결 거부" (macOS 26)

**원인** macOS 26의 "로컬 네트워크" 개인정보 권한이 Docker에 꺼져 있으면 컨테이너에서 같은 네트워크의 다른 장비(서버, 공유기)가 0초 만에 거부되고 인터넷만 된다. Docker 재시작으로는 풀리지 않는다.

**해결** 시스템 설정 → 개인정보 보호 및 보안 → 로컬 네트워크 → Docker 켜기. 목록에 없으면 Docker Desktop을 껐다 켜서 권한 팝업에 "허용". 2026-09-22 학교에서 이 방법으로 srv-na 점검이 바로 성공했다.

## 1-2. Docker 재시작 뒤 API가 `502`이고 로그에 "Name or service not known"

**원인** Docker Desktop이 다시 뜨면서 db 컨테이너가 올라오지 않았다(`Exited (0)`). api는 db를 못 찾아 재시작을 반복한다.

**해결** `docker compose up -d db` 뒤 몇 초 기다리면 api가 스스로 회복한다.

## 1-3. "제품 연결을 확인하세요: … PURL과 CPE가 서로 다른 제품을 가리킵니다"

**원인** 같은 패키지·같은 버전이 두 Ubuntu 릴리스(24.04와 26.04)에 설치되어 PURL의 `distro=` 한정자만 달랐는데, 제품 식별 규칙이 이를 다른 제품으로 보고 검사 저장을 거부했다.

**해결** `distro`·`arch` 한정자는 설치 위치이지 제품 정체성이 아니므로 비교에서 제외했다. 실패한 검사는 "재시도"로 다시 저장된다.

## 2. 로그인부터 `502 Bad Gateway`

**원인** Docker를 재시작하면 api 컨테이너가 새 주소를 받는데, 웹(nginx)이 시작 때 찾아 둔 옛 주소로 계속 보냈다.

**해결** `frontend/nginx.conf`가 요청마다 `api` 주소를 다시 찾도록 바꿨다(`resolver 127.0.0.11`). 이전 이미지를 쓰고 있다면 `docker compose restart web`.

## 3. `TARGET_ARCHITECTURE` · "대상 서버는 분석 워커와 같은 CPU 아키텍처의 Linux여야 합니다"

**원인** 워커(Apple Silicon, arm64)의 syft를 x86_64 EC2에 복사하려 했다.

**해결** 워커 이미지가 amd64·arm64 syft를 모두 갖고 서버의 `uname -sm`에 맞는 것을 복사한다. 워커 이미지를 다시 빌드해야 한다(`docker compose up -d --build worker`).

## 4. `REMOTE_COMMAND_FAILED` · "Please login as the user ubuntu rather than the user root"

**원인** EC2는 root 로그인을 막고 이 문구를 돌려준다. 서버 응답 첫 줄이 오류 메시지에 그대로 붙는다.

**해결** SSH 계정을 `ubuntu`로 바꾼다.

## 5. `SSH_KEY_MISSING` · 관리 서버 키가 없다

**해결** 서버 등록의 인증 방식에서 "비밀번호로 접속 (키 없이)" 또는 "키 파일 첨부"를 고른다. 비밀번호·키는 암호화해 저장하고 첫 접속 때 호스트 키를 기억한다. 서버를 재설치했다면 서버 수정에서 호스트 키를 초기화한다.

## 6. 도메인이 등록은 되는데 접속이 안 된다

**원인** Cloudflare 같은 프록시 뒤의 도메인은 80·443만 열려 있어 22번이 닿지 않는다.

**해결** 서버의 실제 IP나 프록시를 거치지 않는 호스트 이름을 쓴다.

## 7. 새 EC2인데 CVE가 5,359개

**원인** 오류가 아니다. 커널 소스 패키지 하나에 CVE 4,778개가 묶여 있고, Ubuntu가 아직 고치지 않은 "수정판 없음" CVE까지 센다. 실제로 apt로 확인하니 보안 업데이트 124개가 대기 중이라 "수정판 있음" 항목은 진짜였다.

**읽는 법** 결과 표의 "지금 고칠 수 있는 CVE n개 (커널 제외)"가 조치 대상이다. CVE 목록은 기본으로 커널을 빼고, "수정판 있는 CVE만"을 고르면 `apt upgrade`로 없앨 항목만 남는다. 자세한 설명은 `docs/WEB_ANALYSIS.md`의 "CVE 개수 읽는 법".

**근거 자료** (2026-09-21 확인)
- AWS EC2 사용 설명서 "Update instance software": "When you first launch and connect to an Amazon Linux instance, you might see a message asking you to update software packages for security purposes." — 막 만든 인스턴스도 보안 업데이트가 밀려 있을 수 있다는 AWS 자신의 설명. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/install-updates.html
- Ubuntu on AWS 문서: AMI는 "Daily (untested) and release versions of the images are published regularly." 즉 이미지는 만든 시점의 패키지를 담고, 그 뒤 나온 보안 업데이트는 인스턴스에서 받아야 한다. https://ubuntu.com/aws/docs/aws-how-to/instances/find-ubuntu-images/
- Ubuntu 서버 문서 "Automatic updates": unattended-upgrades가 하루 한 번 보안 업데이트를 설치한다. srv-han은 켠 지 몇 시간이라 아직 돌지 않았다. https://ubuntu.com/server/docs/how-to/software/automatic-updates/
- Ubuntu CVE 추적기 안내: 지원하는 모든 Ubuntu 버전에 대해 패키지별 상태를 기록하며, 상태에는 "Needs evaluation", "Vulnerable, fix deferred", "Ignored(won't be fixed)"가 포함된다. 검사 결과의 "수정판 없음"이 바로 이 항목들이다. https://ubuntu.com/security/cves/about
- Grype 문서: 배포판 데이터에는 수정판이 없는 취약점도 들어 있어 fix state가 `fixed / not-fixed / wont-fix / unknown`으로 나뉘고 `--only-fixed`로 걸러 볼 수 있다. https://oss.anchore.com/docs/guides/vulnerability/filter-results/
- 커널 CVE 규모: 커널 프로젝트가 2024년부터 직접 CVE를 발급하면서 연간 3,000~5,700건, 릴리스당 1,000건 이상으로 늘었다(7.0 계열). 커널 패키지 하나에 수천 개가 붙는 이유다. https://linuxcvetracker.com/cve-statistics/ , https://www.tomshardware.com/software/linux/linux-kernel-nears-2-000-cves-per-release-as-ai-bug-hunters-scour-40-million-lines-of-code-maintainers-say-they-are-completely-overwhelmed
- 표본 대조: srv-han 결과에서 무작위 8개 CVE를 Ubuntu 추적기에서 조회해 수정판 버전·상태가 모두 일치했다(예: CVE-2026-8925 curl → released 8.18.0-1ubuntu2.2).

## 8. "버전만 보고 오탐하는 것 아닌가"

**대책** OS 패키지는 Ubuntu가 공개한 패키지 버전 기준 수정 정보로만 대조하고(CPE 대조 끔), 검사 직후 서버의 apt/dnf에게 실제로 올릴 수 있는 버전을 물어 CVE마다 "저장소에 업데이트 있음 / 수정판 미만 / 업데이트 없음 · 오탐 의심"을 남긴다. srv-han은 211개 중 209개가 확인됐고 오탐 의심은 coreutils 하나였다. 커널은 메타 패키지로 올라가므로 판정하지 않는다.

## 9. `EMPTY_COLLECTION` · 잠금 파일을 찾지 못했다

**동작** 소스에 import 문이나 의존성 파일이 있으면 AI가 라이브러리와 버전을 추정해 검사한다(결과에 "AI 라이브러리 참조 · 버전 추정" 표시). 코드 자체가 없는 저장소(예: hello-world)는 이 메시지로 끝나는 것이 정상이다. AI가 꺼져 있거나 실패하면 그 이유가 메시지 뒤에 붙는다.

## 10. AI가 "OPENAI_API_KEY를 설정하세요" 또는 꺼져 있다

**해결** 프로젝트 루트의 `.env`(숨김 파일, 파인더에서 Cmd+Shift+.)에 `OPENAI_API_KEY`를 넣고 `docker compose up -d api worker`. 워커도 같은 설정을 읽으므로 둘을 함께 올린다. Google Gemini는 `OPENAI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/`와 `OPENAI_MODEL=gemini-2.5-flash`로 쓸 수 있다.

## 11. AI 답이 한 문장에서 잘린다

**원인** Gemini·GPT-5 계열은 숨은 추론 토큰을 같은 출력 한도에서 쓴다. 700토큰 한도에 26토큰만 보였다.

**해결** 한도에 여유를 주고, 기본으로 `OPENAI_REASONING_EFFORT=none`을 보내 숨은 추론을 끈다(같은 요약이 1,651토큰에서 260토큰으로 줄었다). 값을 거부하는 모델에는 자동으로 빼고 다시 보낸다.

## 12. "AI 서비스가 지금 혼잡합니다(모델 과부하)"

**원인** Google이 `503 This model is currently experiencing high demand`를 몇 초씩 돌려준다.

**동작** 3번까지 다시 시도한 뒤 이 메시지를 띄운다. SSH 점검의 수집 에이전트는 OS 규칙으로 자동 전환되어 점검은 완료되고, 요약만 잠시 뒤 다시 누르면 된다.

## 13. 검사가 끝나는 순간 다른 화면으로 튄다

**해결** 검사를 시작한 화면에 그대로 있을 때만 결과를 자동으로 열고, 다른 화면에 있으면 "검사 #n 완료" 안내만 띄운다.

## 14. 서버 목록의 CVE 수가 수만 건

**원인** 검사 이력 전체의 연결 건수를 더했다.

**해결** 최신 검사(범위별) 기준으로 CVE를 한 번씩만 센다.

## 15. 서버 언어가 한국어인데 apt 대조가 전부 "오탐 의심"

**원인** apt가 `[upgradable from:]`를 번역해 출력하면 파서가 읽지 못한다.

**해결** 대조 명령이 `LC_ALL=C`로 실행된다.

## 16. 워커가 비밀번호·키를 못 푼다

**원인** api와 worker의 `JWT_SECRET`/`CREDENTIAL_KEY`가 다르면 복호화가 실패한다.

**해결** 두 서비스가 같은 값을 읽도록 compose에 함께 넣었다. `.env`에서 바꾸면 둘 다 다시 올린다.

## 17. 검사 중 "취소됨 · USER_CANCELLED"

**원인** 화면에서 "검사 취소"를 눌렀다. 오류가 아니다. 재시도 버튼으로 새 작업을 만든다.
