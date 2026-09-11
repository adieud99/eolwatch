# EOLWatch 다음 작업 재개 가이드

기준일: 2026-09-12

## 현재 상태

- 핵심 기능은 로컬 Docker 환경에서 실행과 검증을 마쳤다.
- API, PostgreSQL, React 웹, 일일 점검 worker를 컨테이너로 구성했다.
- 자산·소프트웨어·SBOM·통합 위험도·SSH 점검 이력을 구현했다.
- CycloneDX JSON 1.4~1.7 공식 스키마 검증과 SBOM 구성요소 추출을 구현했다.
- AWS 배포용 Terraform과 운영 Compose는 검증했지만 실제 AWS 리소스는 생성하지 않았다.
- 실제 서버 SSH 수집과 인터넷 공개 배포는 아직 진행하지 않았다.

세부 완료 범위와 검증 결과는 `IMPLEMENTATION_STATUS.md`를 기준으로 확인한다.

## 다음에 시작하는 방법

프로젝트 루트에서 다음 명령을 실행한다.

```bash
docker compose up -d
docker compose ps
```

데모 데이터가 필요하면 다음 명령을 한 번 실행한다.

```bash
docker compose exec api python -m app.seed
```

접속 주소는 다음과 같다.

- 웹 화면: <http://localhost:8080>
- API 문서: <http://localhost:8000/docs>
- 상태 확인: <http://localhost:8000/health>

작업을 끝낼 때는 다음 명령으로 컨테이너를 종료한다.

```bash
docker compose down
```

`docker compose down -v`는 PostgreSQL 볼륨의 데이터까지 삭제하므로 데이터 초기화가 필요한 경우에만 사용한다.

## 다음 구현 우선순위

1. 관리자·조회자 로그인과 API 권한 검사
2. 자산 CSV 일괄 등록과 행별 오류 결과
3. SBOM 버전 비교
4. OSV 취약점 조회와 VEX 상태 관리
5. Teams Workflows 알림과 전송 이력
6. 일일 점검 및 지원종료 PDF 보고서
7. 감사 로그
8. 프런트엔드 자동 테스트와 로그인 화면

외부 환경을 사용할 수 있으면 실제 SSH 수집 실증, AWS `terraform plan`, 도메인 연결, S3 백업·복구 훈련 순서로 진행한다. AWS `terraform apply`는 실제 비용과 외부 리소스 생성을 수반한다.

## 제출 자료 작업

- 기존 PPTX와 DOCX를 2차 기획 및 현재 구현 결과에 맞게 갱신한다.
- 웹 대시보드, API 문서, ERD, 아키텍처, 실제 배포 화면을 캡처한다.
- 기능 시연 순서와 발표 대본을 작성한다.
- 외부 환경에서 검증하지 않은 기능은 계획 또는 미검증 상태로 표시한다.

## 종료 시점 검증 기록

- 백엔드 테스트 6개 통과
- React 프로덕션 빌드 통과
- 개발·운영 Compose 설정 검사 통과
- Docker 이미지 빌드와 네 서비스 기동 통과
- Alembic 마이그레이션 통과
- CycloneDX 1.7 생성 문서 공식 스키마 검증 통과
- Terraform 초기화와 구성 검증 통과
