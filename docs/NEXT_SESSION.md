# EOLWatch 작업 재개 안내

기준일: 2026-09-21 (KST). 기준 문서는 [재시작 계획](RESTART_PLAN.md), 전체 구성도와 단계별 진행 기준은 [프로젝트 구성도·단계별 계획](PROJECT_CONFIGURATION_AND_ROADMAP.md), 구현 범위는 [구현 현황](IMPLEMENTATION_STATUS.md)을 따른다.

## 접속 주소

| 환경 | 주소 | 설명 |
|---|---|---|
| 실습(시연) 웹 | <http://127.0.0.1:18080> | 관리 VM. 실제 검사·조치 이력이 있는 DB |
| 맥 개발 웹 | <http://127.0.0.1:8080> | 시연과 **별도 DB** |
| 맥 개발 API | <http://127.0.0.1:8000/docs> | FastAPI 문서 |

## 직전 세션에서 반영한 내용

- 솔루션을 **개발 및 인프라 취약점 검사**로 재정의하고 메뉴를 개요·개발 검사·인프라 검사·검사 기록·관리로 재구성 (커밋 `73c10b5`)
- EOL 일정·공개 EOL 카탈로그·자산 재고·위험 점수·고객·사이트·제품·계약·소프트웨어 원장·Teams 알림·EOL/점검/자산 PDF·CSV 등록 코드와 DB 테이블 제거 (Alembic `d2f8c4a71e9b`)
- 서버(Asset)는 식별·SSH 접속 정보만 보관. 서버 등록 폼을 접속 정보로 축소
- 인프라 검사 서버 정보 수집: collector에 호스트·커널·CPU·메모리·디스크 총량·가상화·DMI·EC2 메타데이터·IP·수신 포트·실행 서비스 명령과 파서 추가, `raw_metrics.server_info`에 저장, 테스트 추가
- 문서를 새 프레임으로 정리

검사 결과: 백엔드 **363 passed** (격리 컨테이너), 프런트엔드 **102 passed**, 프런트엔드 빌드 성공 (2026-09-21).

**관리 VM(18080)에 재범위화 코드를 배포하고 브라우저로 두 흐름을 끝까지 확인한 상태는 아니다.** 배포 시 `alembic upgrade head`가 `d2f8c4a71e9b`를 적용해 제거 대상 테이블·컬럼을 삭제하므로 배포 전에 DB 백업을 남긴다.

AI는 기본으로 OpenAI를 쓴다. `.env`에 `OPENAI_API_KEY`와 `OPENAI_MODEL`을 넣는다(키는 git에 올라가지 않는다). Claude는 `AI_PROVIDER=anthropic`과 `ANTHROPIC_API_KEY`를 넣는다. 파이프라인 안 AI(잠금 파일 없는 소스의 라이브러리 참조, SSH 점검의 수집 에이전트)는 구현되어 같은 제공자를 쓴다. 워커도 AI 설정을 읽으므로 `.env`를 바꾸면 api·worker를 함께 다시 올린다.

## 다음 작업 (2026-09-22부터)

2026-09-21에 화면 전체를 헤드리스 브라우저로 눌러 보는 점검과 코드 리뷰를 끝냈고 찾은 문제는 모두 고쳐 푸시했다(`docs/TROUBLESHOOTING.md`). 남은 것은 코드가 아니라 운영·시연이다.

1. **학교에서 srv-na 확인.** 192.168.217.245는 학교 내부망 주소라 같은 Wi-Fi에서만 붙는다. "SSH 점검" → "취약점 검사" 순서. Wi-Fi를 바꾼 직후 컨테이너가 "연결 거부"를 내면 Docker Desktop을 완전히 껐다 켠다.
2. **srv-han 전후 비교 시연 준비.** 서버에서 `sudo apt update && sudo apt upgrade -y && sudo reboot` 후 재검사하면 "지금 고칠 수 있는 CVE 211개"가 0 근처로, 커널 CVE도 크게 줄어든다. 검사 기록의 "검사 전후 비교"와 PDF가 시연 장면이다. 교수님의 "새 EC2에 CVE가 이렇게 많을 리 없다"는 질문에는 `TROUBLESHOOTING.md` 7·8번의 근거(AWS·Ubuntu 문서, apt 대조 결과, 표본 대조)로 답한다.
3. **AI 한도.** Gemini 무료 등급은 하루 20회라 시연 날 요약을 여러 번 누르지 않거나, 결제를 켜거나, `OPENAI_MODEL`을 바꾼다. SSH 점검·취약점 검사는 AI가 없어도 완료된다.
4. **(선택) 학교 VM 배포.** 집에서도 srv-na를 검사하려면 필요하다(`DEPLOYMENT.md`).
5. **발표 자료는 맨 마지막.** 교수님 8단계 순서(개요 → 솔루션 전체 구성도 → 시스템 구성도 → 서비스 구성도 → 서비스 설명 → 인프라 설명 → 추가 서비스 → 마무리)로 작성한다. 화면 대응은 [교수님 설명 안내](PROFESSOR_PROJECT_GUIDE.md) 9절을 쓴다.

## 코드 작업 후 검증·배포

맥에서 검사한다.

```bash
sh scripts/test-backend.sh                  # 격리 컨테이너에서 백엔드 전체 테스트
cd frontend && npm test && npm run build    # 프런트엔드 테스트와 빌드
```

맥 개발 환경에 반영한다.

```bash
docker compose up --build -d
docker compose ps
curl -s http://127.0.0.1:8000/health
```

`docker compose down -v`는 PostgreSQL 볼륨까지 지우므로 데이터 초기화가 필요할 때만 쓴다.

관리 VM에 코드만 갱신할 때는 **초기 배포용 `deploy-to-lab.sh`를 쓰지 않는다.** 변경한 소스·의존성·마이그레이션만 SSH/SCP로 전달하고 `/opt/eolwatch`에서 `sudo docker compose up --build -d`를 실행한 뒤, `status.sh`와 브라우저로 기동·기존 검사 이력을 확인한다. 기존 `.env`, SSH 키·known_hosts, PostgreSQL·검사 원본 볼륨은 유지한다. 절차 전문은 [로컬 VM 환경](../infrastructure/local-vm/README.md)에 있다.

DB·원본 ZIP 백업과 복구 검증은 [운영 백업](BACKUP_OPERATIONS.md)의 명령을 그대로 쓴다.

## 발표 자료 작업

- 발표 자료는 현재 검사 흐름(ZIP/SSH → Syft → SPDX 2.3 → Grype)과 검증된 화면을 기준으로 구성한다. 이전 4장 제안 요약서 작업은 버렸다.
- 외부 환경에서 검증하지 않은 기능은 계획 또는 미검증 상태로 표시한다.
