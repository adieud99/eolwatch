# EOLWatch 작업 재개 안내

기준일: 2026-09-16 (KST). 전체 구성도와 단계별 진행 기준은 [프로젝트 구성도·단계별 계획](PROJECT_CONFIGURATION_AND_ROADMAP.md), 구현 범위는 [구현 현황](IMPLEMENTATION_STATUS.md)을 따른다.

## 접속 주소

| 환경 | 주소 | 설명 |
|---|---|---|
| 실습(시연) 웹 | <http://127.0.0.1:18080> | 관리 VM. 실제 분석·조치 이력이 있는 DB |
| 맥 개발 웹 | <http://127.0.0.1:8080> | 시연과 **별도 DB** |
| 맥 개발 API | <http://127.0.0.1:8000/docs> | FastAPI 문서 |

## 직전 세션에서 반영한 내용

- 프로젝트별 전체 분석 이력·검색·페이지 이동·과거 비교
- 저장 ZIP 원본 다운로드·재분석·저장소 현황
- 분석 취소와 프로세스 종료 확인, 예약 처리 보완
- 공개 EOL 일정 조회·미리보기·적용·원본과 변경 근거 보관
- 제품 버전·식별자 연결 정확성, 현재 위험과 누적 이력 구분
- 웹·PDF 지원 종료 계산 통일, 동시 ZIP 업로드 문제 수정

검사·배포 결과: 백엔드 394개 + 프런트엔드 120개 = **514개 통과**, 프런트엔드 빌드 성공, 실습 서버와 맥 개발 환경 반영 완료. PostgreSQL 마이그레이션 `a16c902bf743`, 모델 비교 이상 없음. 종료 시 활성 분석 0건, 예약 #1 일시 중지 상태.

종료 시점 백업·임시 복원 검증 성공: `/opt/eolwatch/backups/eolwatch-runtime-20260915T160237Z-0a1d01323c71`.

**전체 코드 검사와 배포는 완료했지만, 아래 브라우저 시나리오 전체 통과를 확인한 상태는 아니다.**

## 다음 작업: 실제 브라우저 검증 마무리

1. 프로젝트 목록 화면 정상 표시 확인. 자동화 스크립트가 label 선택에서 멈췄으므로 **ZIP 원본 다운로드·재분석·과거 비교·SBOM 이동**을 이어서 검증한다.
2. **실행 중 분석 취소의 실제 VM 검증은 미시작.** 기능 설명은 [분석 취소와 정리 확인](ANALYSIS_CANCELLATION.md)에 있다.
3. EOL 공개 목록 갱신은 성공했으나 **개별 제품 조회·미리보기·적용은 미시작.** 숨겨진 `<option>`을 기다리는 검증 스크립트를 먼저 고친다. 중단 지점·스크립트 경로·재사용할 ID는 [EOL 카탈로그 검증 인계](LIFECYCLE_CATALOG_HANDOFF.md)를 따른다.
4. EOL 검증용 **제품 #1381 / SBOM #23 / 구성요소 #5537 / 비활성 VERIFY 자산 #4**를 재사용한다. 스크립트를 그대로 다시 돌리면 검증용 제품이 중복 생성되므로 준비 단계를 먼저 조정한다.

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

`docker compose down -v`는 PostgreSQL 볼륨까지 지우므로 데이터 초기화가 필요할 때만 쓴다. 데모 데이터는 `docker compose exec api python -m app.seed`로 한 번만 넣는다.

관리 VM에 코드만 갱신할 때는 **초기 배포용 `deploy-to-lab.sh`를 쓰지 않는다.** 변경한 소스·의존성·마이그레이션만 SSH/SCP로 전달하고 `/opt/eolwatch`에서 `sudo docker compose up --build -d`를 실행한 뒤, `status.sh`와 브라우저로 기동·기존 분석 이력을 확인한다. 기존 `.env`, SSH 키·known_hosts, PostgreSQL·분석 원본 볼륨은 유지한다. 절차 전문은 [로컬 VM 환경](../infrastructure/local-vm/README.md)에 있다.

DB·원본 ZIP 백업과 복구 검증은 [운영 백업](BACKUP_OPERATIONS.md)의 명령을 그대로 쓴다.

## 제출 자료 작업

- 요약서 정본은 [EOLWatch_프로젝트요약서_김연동_수정본.pdf](EOLWatch_프로젝트요약서_김연동_수정본.pdf)이며, 원본 소스는 같은 폴더의 `EOLWatch_프로젝트요약서.html`이다. 내용을 고칠 때는 HTML을 수정하고 다시 인쇄한다.
- 발표 자료는 현재 분석 흐름(Syft → SPDX 2.3 → Grype)과 검증된 화면을 기준으로 구성한다. 교수님 설명 순서는 [교수님 설명 안내](PROFESSOR_PROJECT_GUIDE.md)를 따른다.
- 외부 환경에서 검증하지 않은 기능은 계획 또는 미검증 상태로 표시한다.
