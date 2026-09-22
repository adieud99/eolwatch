# 타깃층과 라이선스 확인

교수님 질문: "타겟층: 고객사가 쓰나, 자사만 쓰나? 라이선스 확인이 중요하다."
이 문서는 그 질문에 저장소와 실행 중인 컨테이너에서 직접 읽은 값으로 답한다. 확인 일자는 2026-09-22이고, 확인 명령은 맨 끝 "확인 방법"에 적었다.

## 1. 타깃층

EOLWatch는 두 가지 형태로 쓸 수 있다. 코드는 같지만 라이선스와 데이터 취급이 달라진다.

| 구분 | A. 자사 내부 운영팀 | B. 고객사 서버를 대신 검사하는 서비스 |
|---|---|---|
| 검사 대상 | 자기 회사 서버(SSH)와 자기 소스(ZIP 업로드) | 고객사 서버와 고객사 소스 |
| 배포 형태 | 배포 없음. 자기 서버에서 docker compose로 실행 | 우리가 운영하는 서버에서 서비스 제공(SaaS) 또는 고객사에 설치 |
| 오픈소스 라이선스 의무 | 대부분의 라이선스는 "배포"할 때 의무가 생긴다. 내부 실행만 하면 고지 의무가 거의 없다 | 고객사에 설치본을 넘기면 "배포"다. 아래 2절의 배포 시 의무가 모두 적용된다. SaaS만 하면 코드 배포는 아니지만 데이터 출처 attribution(3절)은 화면·보고서에 필요하다 |
| 데이터 소유 | 패키지 목록·호스트명·IP·CVE 결과가 모두 자사 것 | 고객사 자산 정보다. 보관 위치, 보관 기간, 삭제 요청 처리, 접근 권한을 계약에 적어야 한다 |
| AI 제공자 | 자사 판단으로 외부 API 사용 여부 결정 | 고객사 서버 정보가 OpenAI·Anthropic 등 제3자에게 전송된다. 고객 동의와 제공자 약관 확인이 필요하다 |
| 현재 범위 | 문서화된 범위 안이다 | `docs/ARCHITECTURE.md` 7절이 "공개 다중 조직 SaaS는 현재 범위 밖"이라고 적고 있다. 조직 분리(테넌트) 기능이 없다 |

### 1-1. 제품 자체의 라이선스가 없다

저장소 최상위에 `LICENSE` 파일이 없다(`ls LICENSE*` 결과 없음). `frontend/package.json`은 `"private": true`이고 `license` 필드가 없다. 지금 상태로 코드를 밖에 내보내면 받는 쪽이 어떤 조건으로 쓸 수 있는지 정해져 있지 않다.

A 형태(자사 내부)는 라이선스 파일이 없어도 문제가 없다. B 형태로 가기 전에는 둘 중 하나를 정해서 `LICENSE`를 넣어야 한다.

- 공개할 생각이면 Apache-2.0. 사용 도구(Syft, Grype)와 같은 라이선스라 섞어 쓰기 쉽고, 특허 조항이 있다.
- 공개할 생각이 없으면 독점(proprietary) 라이선스 문구. 이 경우에도 아래 2절의 서드파티 고지 파일은 같이 넘겨야 한다.

### 1-2. AI 제공자에게 나가는 데이터

`backend/app/services/ai_advisor.py`가 외부 AI API에 보내는 내용을 코드에서 읽었다.

- 소스 검사 요약(`analysis_context`): 자산 태그, 라이브러리 이름·버전, CVE ID·요약(60자), 수정 버전, 심각도 집계. 심각도 순 15개 라이브러리까지만 보낸다.
- 서버 점검 요약(`check_context`): 호스트명, IP 주소 목록, OS 이름, 커널, 아키텍처, CPU 모델·코어 수, 메모리 크기, 가상화·클라우드 제공자·인스턴스 유형·리전, 열린 포트(15개), 서비스(12개), 상위 프로세스 이름(5개), 디스크 사용률, 수집 에이전트 출력(8건, 각 160자), 실패 메시지.
- 제공자: `AI_PROVIDER=openai`(기본, `OPENAI_BASE_URL`로 OpenAI 호환 서버도 가능) 또는 `anthropic`. 키는 `.env`에만 둔다.
- 같은 프롬프트(SHA-256 일치)면 저장된 답을 재사용하고 다시 보내지 않는다.

고객사 서버를 검사하는 B 형태에서는 호스트명·IP·열린 포트가 제3자 API로 나간다는 점을 고객에게 알리고 동의를 받아야 한다. 보내는 데이터의 범위와 줄인 방법은 `docs/TOKEN_DIET.md` 2-1절에, 저장 위치(볼륨)와 백업 범위는 `docs/ARCHITECTURE.md` 7절에 있다. `AI_PIPELINE=false`로 끄면 AI 호출 없이 검사만 한다.

## 2. 사용 도구·라이브러리 라이선스

값은 모두 실행 중인 `api` 컨테이너의 패키지 메타데이터(`License-Expression`, `License`, `Classifier`), `frontend/node_modules/*/package.json`의 `license` 필드, 각 프로젝트 GitHub 저장소의 LICENSE 파일에서 읽었다. 추측한 값은 없다.

### 2-1. 요약

| 항목 | 결과 |
|---|---|
| Python 배포판 수(api 컨테이너) | 57개 |
| 그중 GPL | 0개 |
| 그중 LGPL | 3개: paramiko(LGPL-2.1), psycopg·psycopg-binary(LGPL-3.0) |
| 그중 MPL-2.0 | 1개: certifi |
| 나머지 | MIT, BSD, Apache-2.0, PSF-2.0, MIT-0, MIT-CMU |
| Node 패키지 수(node_modules) | 116개. MIT 99, Apache-2.0 4, ISC 3, BSD-2 2, BSD-3 2, MIT-0 2, MPL-2.0 2(lightningcss, 빌드 도구), BlueOak-1.0.0 1(lru-cache), CC0-1.0 1(mdn-data) |
| 실제 배포되는 Node 코드 | `dist/`에는 react, react-dom만 번들된다. 나머지는 빌드·테스트용이라 배포물에 들어가지 않는다 |
| 외부 도구 | Syft 1.52.0, Grype 0.119.0 모두 Apache-2.0 |
| 상업적 사용 | 위 라이선스 전부 상업적 사용 가능. 금지 조항이 있는 것은 없다 |

### 2-2. 백엔드 직접 의존성 (`backend/requirements.txt`)

| 이름 | 버전 | 라이선스 | 상업적 사용 | 배포 시 의무 |
|---|---|---|---|---|
| fastapi | 0.116.1 | MIT (Classifier) | 가능 | 저작권 고지 유지 |
| alembic | 1.16.5 | MIT | 가능 | 저작권 고지 유지 |
| uvicorn | 0.35.0 | BSD-3-Clause | 가능 | 저작권 고지 유지, 이름을 홍보에 쓰지 않음 |
| SQLAlchemy | 2.0.43 | MIT | 가능 | 저작권 고지 유지 |
| psycopg / psycopg-binary | 3.2.9 | LGPL-3.0 | 가능 | 수정 없이 import해서 쓰면 우리 코드는 LGPL이 되지 않음. 라이브러리를 고쳐서 배포하면 그 수정분 소스 공개. 사용자가 라이브러리를 교체할 수 있어야 함(pip 설치 구조라 충족) |
| pydantic | 2.13.5 | MIT | 가능 | 저작권 고지 유지 |
| pydantic-settings | 2.10.1 | MIT | 가능 | 저작권 고지 유지 |
| python-multipart | 0.0.31 | Apache-2.0 | 가능 | LICENSE·NOTICE 유지, 수정 시 표시 |
| APScheduler | 3.11.0 | MIT | 가능 | 저작권 고지 유지 |
| paramiko | 5.0.0 | LGPL-2.1 | 가능 | psycopg와 같음. SSH 접속에 쓰며 수정하지 않았다 |
| jsonschema | 4.25.1 | MIT | 가능 | 저작권 고지 유지 |
| httpx | 0.28.1 | BSD-3-Clause | 가능 | 저작권 고지 유지 |
| reportlab | 4.4.4 | BSD (메타데이터 "BSD license (see license.txt)") | 가능 | 저작권 고지 유지 |
| packaging | 25.0 | Apache-2.0 또는 BSD (Classifier 둘 다) | 가능 | 둘 중 택일, 고지 유지 |
| packageurl-python | 0.17.6 | MIT | 가능 | 저작권 고지 유지 |
| anthropic | 1.7.0 | MIT | 가능 | 저작권 고지 유지 |

### 2-3. 눈여겨볼 간접 의존성

| 이름 | 버전 | 라이선스 | 비고 |
|---|---|---|---|
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | paramiko가 사용 |
| bcrypt | 5.0.0 | Apache-2.0 | paramiko가 사용 |
| PyNaCl | 1.6.2 | Apache-2.0 | paramiko가 사용 |
| starlette | 0.47.3 | BSD-3-Clause | fastapi가 사용 |
| certifi | 2026.7.22 | MPL-2.0 | 파일 단위 copyleft. 수정 없이 쓰면 고지만 하면 됨 |
| pillow | 12.3.0 | MIT-CMU | reportlab이 사용 |
| typing_extensions | 4.16.0 | PSF-2.0 | |
| greenlet | 3.5.6 | MIT AND PSF-2.0 | SQLAlchemy가 사용 |
| cffi | 2.1.1 | MIT-0 | 고지 의무 없음 |

### 2-4. 프런트엔드 (`frontend/package.json`)

| 이름 | 버전 | 라이선스 | 배포물 포함 | 배포 시 의무 |
|---|---|---|---|---|
| react | 19.3.0 | MIT | 포함(dist 번들) | 저작권 고지 유지 |
| react-dom | 19.3.0 | MIT | 포함(dist 번들) | 저작권 고지 유지 |
| vite | 8.3.0 | MIT | 빌드 도구, 미포함 | 없음 |
| @vitejs/plugin-react | 6.1.1 | MIT | 빌드 도구, 미포함 | 없음 |
| vitest | 4.1.11 | MIT | 테스트, 미포함 | 없음 |
| @testing-library/react | 16.3.3 | MIT | 테스트, 미포함 | 없음 |
| @testing-library/jest-dom | 6.9.1 | MIT | 테스트, 미포함 | 없음 |
| @testing-library/dom | 10.4.2 | MIT | 테스트, 미포함 | 없음 |
| jsdom | 27.4.0 | MIT | 테스트, 미포함 | 없음 |
| lightningcss | 1.33.0 | MPL-2.0 | vite 내부 빌드 도구, 미포함 | 없음 |

### 2-5. 외부 도구, 글꼴, 인프라

| 구분 | 이름 | 버전 | 라이선스 | 근거 | 상업적 사용 | 배포 시 의무 |
|---|---|---|---|---|---|---|
| 도구 | Syft | 1.52.0 | Apache-2.0 | github.com/anchore/syft LICENSE | 가능 | 바이너리를 같이 넘기면 LICENSE·NOTICE 동봉. GitHub 릴리스에서 체크섬 검증 후 설치(`backend/tools/install_anchore.py`) |
| 도구 | Grype | 0.119.0 | Apache-2.0 | github.com/anchore/grype LICENSE | 가능 | 위와 같음 |
| 도구 | grype-db(DB 빌드 도구) | | Apache-2.0 | github.com/anchore/grype-db LICENSE | 가능 | 코드 라이선스다. 배포되는 DB 파일의 이용 조건은 3절 참고 |
| 글꼴 | Nanum Gothic Regular/Bold | | SIL OFL 1.1 | `backend/app/resources/fonts/OFL.txt` (저작권 NHN 2010, 예약 글꼴 이름 있음) | 가능 | 글꼴 단독 판매 금지. 소프트웨어·문서에 포함해 배포하는 것은 허용. OFL.txt를 같이 둔다(현재 저장소에 있음). PDF 비교 보고서에 포함(`comparison_report_pdf.py`) |
| 글꼴 | Pretendard | 1.3.9 | OFL-1.1 | jsDelivr `pretendard@1.3.9/package.json` license 필드 | 가능 | 저장소에 파일을 두지 않고 `frontend/src/styles.css`에서 CDN으로 불러온다. 고객사 폐쇄망 설치 시 CDN이 안 열리면 글꼴만 시스템 기본으로 바뀐다 |
| DB | PostgreSQL | 16 (prod 16.10) | PostgreSQL License | github.com/postgres/postgres COPYRIGHT ("Permission to use, copy, modify, and distribute ... for any purpose, without fee") | 가능 | 저작권 고지 유지 |
| 웹 서버 | nginx | 1.27 | BSD-2-Clause | github.com/nginx/nginx LICENSE (조건 2개) | 가능 | 저작권 고지 유지 |
| 웹 서버(prod) | Caddy | 2.10 | Apache-2.0 | github.com/caddyserver/caddy LICENSE | 가능 | LICENSE·NOTICE 유지 |
| 기반 이미지 | python:3.12-slim, node:22-alpine, postgres:16-alpine, nginx:1.27-alpine, caddy:2.10-alpine | | 이미지 안 OS 패키지마다 다름 | Docker 공식 이미지 | 가능 | 이미지를 그대로 내려받아 실행하는 형태라 별도 의무 없음. 이미지를 우리가 다시 배포하면 안의 패키지 라이선스 목록이 필요하다(확인 필요) |

## 3. 취약점 데이터 출처와 이용 조건

Grype는 Anchore가 `vunnel`로 공개 피드를 모아 만든 DB를 `https://grype.anchore.io/databases/v6/`에서 내려받는다. worker 컨테이너에서 읽은 현재 DB는 스키마 v6.1.9, 빌드 2026-09-21T06:39Z, vunnel 0.63.0이고 공급자(provider)는 26개다: alma, alpine, amazon, arch, bitnami, chainguard, chainguard-libraries, debian, echo, eol, epss, fedora, github, govulndb, hummingbird, kev, mariner, minimos, nvd, oracle, photon, rhel, secureos, sles, ubuntu, wolfi.

EOLWatch가 화면·보고서에 실제로 쓰는 값은 CVE(NVD·배포판 추적기), GitHub Advisory(GHSA), KEV 여부, EPSS 점수(`cve_breakdown.py`의 `kev_cve_count`, `epss_cve_count`)다. 검사 대상은 Ubuntu 서버와 업로드된 소스라서 실무에서 매칭되는 출처는 ubuntu, nvd, github, epss, kev가 대부분이다.

| 출처 | 제공자 | 이용 조건 | 확인 근거 | 상업적 사용 | 우리가 할 일 |
|---|---|---|---|---|---|
| NVD | 미국 NIST | 미국 정부 저작물. NIST 사이트 정보는 "public information and may be distributed or copied". 출처 표기는 요청 사항(requested) | nist.gov/oism/copyrights | 가능 | 출처 표기 권장. 미국 밖 저작권 예외는 명시되지 않음 |
| GitHub Advisory Database | GitHub | CC-BY-4.0 | github/advisory-database LICENSE.md | 가능 | 화면·보고서에 출처 표기(attribution) 필수 |
| CISA KEV | 미국 CISA | CC0 1.0. "any legal manner" 허용, 상업적 사용 명시 | cisa.gov/sites/default/files/licenses/kev/license.txt | 가능 | 의무 없음. CISA 로고·DHS 인장 사용 금지, 보증하는 것처럼 표현 금지 |
| EPSS | FIRST.org | CSV·API로 무료, 등록 불필요. "Attribution is requested when EPSS data is used in publications or products" | first.org/epss/faq | 가능 | 제품·보고서에 EPSS 출처 표기 |
| Ubuntu CVE Tracker | Canonical | 저장소 트리에 LICENSE·COPYING 파일 없음. Canonical IP 정책은 소프트웨어·상표만 다루고 데이터는 언급하지 않음 | git.launchpad.net/ubuntu-cve-tracker 트리, canonical.com/legal/intellectual-property-policy | 확인 필요 | 확인 필요. 실무에서 가장 많이 매칭되는 출처이므로 상용 전 Canonical에 문의하거나 데이터 이용 조건 문서를 찾아야 한다 |
| Debian Security Tracker | Debian | 추적기 페이지와 README에서 라이선스 문구를 찾지 못함 | security-tracker.debian.org | 확인 필요 | 확인 필요 |
| Alpine secdb | Alpine Linux | CC BY-SA 4.0 | secdb.alpinelinux.org/license.txt | 가능 | 출처 표기. 이 데이터를 가공해 재배포하면 같은 라이선스(ShareAlike) 적용. Grype DB 안에서만 쓰고 재배포하지 않으면 해당 없음 |
| 그 외 19개(rhel, sles, oracle, amazon, alma, fedora, arch, photon, wolfi, chainguard, mariner, minimos, echo, bitnami, govulndb, hummingbird, secureos, eol 등) | 각 배포판·업체 | 이번에 확인하지 않음 | | 확인 필요 | 현재 검사 대상(Ubuntu)에서는 매칭되지 않는다. 대상 OS를 늘릴 때 그 출처만 확인하면 된다 |
| Anchore 배포 DB 파일 자체 | Anchore | 빌드 도구는 Apache-2.0이지만 DB 파일의 별도 이용약관 문서는 찾지 못함 | grype README, grype-db LICENSE | 확인 필요 | Grype가 자동으로 내려받아 로컬 캐시(`analysis_cache` 볼륨)에서만 쓴다. DB 파일을 고객에게 재배포하지 않는다 |

## 4. 결론

### 4-1. 자사 내부 사용(A)

제약이 없다. 모든 라이브러리·도구가 상업적 사용을 허용하고, 배포를 하지 않으므로 고지 의무도 생기지 않는다. GPL 코드는 없고 LGPL 3개(paramiko, psycopg, psycopg-binary)는 수정 없이 import해서만 쓴다. 외부 AI API에 자사 서버 정보가 나가는 것만 자사 보안 정책에 맞는지 결정하면 된다.

### 4-2. 고객사 대상 상용 서비스(B) 전에 확인할 것

1. 제품 라이선스를 정하고 `LICENSE` 파일을 넣는다(1-1절).
2. 서드파티 고지 파일(예: `THIRD_PARTY_NOTICES.md`)을 만들어 배포물에 동봉한다. 2절 표의 항목, Apache-2.0 도구의 NOTICE, 글꼴 OFL 전문을 담는다. 이 문서의 "확인 방법" 명령으로 목록을 뽑을 수 있다.
3. 화면과 PDF 보고서에 데이터 출처를 표기한다. GitHub Advisory(CC-BY-4.0)는 필수, EPSS와 NVD는 요청 사항이다.
4. Ubuntu CVE Tracker와 Debian 추적기 데이터의 이용 조건을 확인한다. Ubuntu는 주 검사 대상이라 가장 먼저 확인해야 한다.
5. AI 제공자 약관을 확인하고 고객 동의를 받는다. 호스트명·IP·포트·패키지 이름이 OpenAI 또는 Anthropic API로 나간다(1-2절). 고객이 원하면 `AI_PIPELINE=false`로 끄거나 고객 지정 OpenAI 호환 서버(`OPENAI_BASE_URL`)를 쓴다.
6. 고객 데이터 보관 위치를 정한다. 현재는 단일 PostgreSQL과 볼륨 4개에 모든 고객 데이터가 같이 들어가고 조직 분리가 없다(`docs/ARCHITECTURE.md` 7절). 고객사별 설치(각자 docker compose)가 현재 구조에 맞고, 한 서버에서 여러 고객을 받으려면 테넌트 분리를 먼저 만들어야 한다.
7. Syft·Grype 바이너리와 Docker 기반 이미지를 고객에게 그대로 넘긴다면 그 안의 라이선스 목록도 고지에 포함한다.

## 확인 방법

같은 결과를 다시 뽑는 명령이다. 저장소 루트에서 실행한다.

```sh
# 제품 라이선스 파일 유무
ls LICENSE* NOTICE*

# Python: api 컨테이너에 설치된 모든 배포판의 라이선스 메타데이터
docker compose exec -T api python - <<'PY'
import importlib.metadata as m
for d in sorted(m.distributions(), key=lambda d: d.metadata["Name"].lower()):
    md = d.metadata
    lic = md.get("License-Expression") or md.get("License") or ""
    cls = ";".join(c.split("::")[-1].strip() for c in (md.get_all("Classifier") or []) if c.startswith("License"))
    print(md["Name"], d.version, lic.replace("\n", " ")[:60], cls, sep="\t")
PY

# Node: node_modules 안 모든 package.json의 license 필드 집계
cd frontend && node -e '
const fs=require("fs"),path=require("path"),out={};
const walk=d=>{for(const n of fs.readdirSync(d)){const p=path.join(d,n);if(n.startsWith("@")){walk(p);continue;}
 const pj=path.join(p,"package.json");if(fs.existsSync(pj)){const j=JSON.parse(fs.readFileSync(pj));let l=j.license||"UNKNOWN";
 if(typeof l==="object")l=l.type;(out[l]=out[l]||[]).push(j.name+"@"+j.version);}
 const nm=path.join(p,"node_modules");if(fs.existsSync(nm))walk(nm);}};
walk("node_modules");for(const [k,v] of Object.entries(out).sort())console.log(k,v.length,v.join(", "));'

# 도구 버전과 Grype DB 공급자 목록 (worker 컨테이너)
docker compose exec -T worker /opt/analysis-tools/syft version
docker compose exec -T worker /opt/analysis-tools/grype version
docker compose exec -T worker sh -c 'GRYPE_DB_CACHE_DIR=/var/cache/eolwatch/grype-db /opt/analysis-tools/grype db status'
docker compose exec -T worker sh -c 'GRYPE_DB_CACHE_DIR=/var/cache/eolwatch/grype-db /opt/analysis-tools/grype db providers'

# 글꼴
head -12 backend/app/resources/fonts/OFL.txt
grep -n pretendard frontend/src/styles.css
curl -s https://cdn.jsdelivr.net/npm/pretendard@1.3.9/package.json | grep '"license"'

# 외부 라이선스 파일 (2026-09-22 확인)
#  https://raw.githubusercontent.com/anchore/syft/main/LICENSE            Apache-2.0
#  https://raw.githubusercontent.com/anchore/grype/main/LICENSE           Apache-2.0
#  https://raw.githubusercontent.com/anchore/grype-db/main/LICENSE        Apache-2.0
#  https://raw.githubusercontent.com/postgres/postgres/master/COPYRIGHT   PostgreSQL License
#  https://raw.githubusercontent.com/nginx/nginx/master/LICENSE           BSD-2-Clause
#  https://raw.githubusercontent.com/caddyserver/caddy/master/LICENSE     Apache-2.0
#  https://github.com/github/advisory-database/blob/main/LICENSE.md       CC-BY-4.0
#  https://www.cisa.gov/sites/default/files/licenses/kev/license.txt      CC0 1.0
#  https://www.first.org/epss/faq                                         무료, attribution 요청
#  https://www.nist.gov/oism/copyrights                                   NIST 정보 public, 출처 표기 요청
#  https://secdb.alpinelinux.org/license.txt                              CC BY-SA 4.0
#  https://git.launchpad.net/ubuntu-cve-tracker/tree/                     LICENSE 파일 없음 (확인 필요)
```
