# EOLWatch 구현 현황

기준일: 2026-09-12

## 완료

### 기획·설계

- 시스원 인프라 통합유지관리 업무에 맞춘 2차 기획
- 시스템 컨텍스트·논리·배포·수집·SBOM 흐름 아키텍처
- 고객사·자산·SBOM 및 운영·취약점 목표 ERD
- 기술 스택, 배포, 백업·복구 절차

### 데이터베이스·API

- PostgreSQL과 SQLite 개발 모드
- Alembic 초기 마이그레이션
- 고객사와 사이트 등록·조회
- 자산 등록·조회·수정·삭제
- 제품 릴리스와 EOL/EOSL 근거 관리
- 인프라 소프트웨어와 자산 배포 관계
- 유지보수 계약과 대상 자산 연결
- 제품 릴리스에서 영향 자산 역추적
- 통합 위험도 대시보드 집계

현재 OpenAPI 경로는 20개다.

### SBOM

- CycloneDX JSON 1.4~1.7 가져오기
- CycloneDX 공식 JSON Schema 전체 검증
- 원본 JSON 보존
- 중첩 구성요소와 의존관계 추출
- purl·CPE·공급사·이름·버전 기반 제품 릴리스 정규화
- SBOM 품질 프로파일과 누락 항목 계산
- 구성요소 EOL 근거 입력
- 구성요소 → SBOM → 영향 자산 탐색
- SSH 패키지 목록 → CycloneDX 1.7 SBOM 생성

### 인프라 점검

- Paramiko SSH 키 인증
- known_hosts 엄격 검사 기본값
- CPU·메모리·디스크·가동시간·프로세스·패키지 조회 명령
- 접속·인증·명령·파싱 실패 구분
- 점검 작업과 결과 이력 저장
- 수동 점검 API와 화면
- APScheduler 일일 점검 워커

실제 원격 서버에는 아직 접속하지 않았으며 파서와 실패 처리, SBOM 변환을 로컬 테스트로 검증했다.

### 화면

- 통합 위험도 현황
- 고객사·사이트 등록
- 인프라 자산 등록과 수동 점검
- 인프라 소프트웨어 등록과 자산 연결
- SBOM 업로드와 품질 결과
- 점검 이력
- 모바일 레이아웃

### 배포·운영

- 개발용 Docker Compose
- Caddy HTTPS가 포함된 운영 Compose
- API와 별도 스케줄러 worker
- Terraform VPC·보안그룹·EC2·Elastic IP·S3·SSM IAM 구성
- `pg_dump → S3` 백업과 복구 스크립트
- GitHub Actions 백엔드·프런트·컨테이너 CI
- 합성 시연 데이터 생성 명령

Terraform은 AWS provider 5.100으로 `init`과 `validate`를 통과했다. 실제 `apply`는 수행하지 않았다.

## 검증 결과

| 검사 | 결과 |
|---|---|
| 백엔드 테스트 | 6개 통과 |
| CycloneDX 1.7 생성 문서 공식 스키마 검증 | 통과 |
| Alembic upgrade→downgrade→upgrade | 통과 |
| Alembic 모델 변경 누락 검사 | 변경 없음 |
| React 프로덕션 빌드 | 통과 |
| 개발·운영 Compose 설정 검사 | 통과 |
| API·웹·DB·worker 이미지 빌드 | 통과 |
| PostgreSQL 마이그레이션과 API 기동 | 통과 |
| 합성 데이터 대시보드 집계 | 통과 |
| Terraform validate | 통과 |

## 남은 작업

### 구현 필요

1. 관리자·조회자 로그인과 API 권한 검사
2. 자산 CSV 일괄 등록과 행별 오류 보고
3. SBOM 버전 간 구성요소 추가·삭제·변경 비교
4. OSV 취약점과 VEX 상태
5. Teams Workflows 알림과 전송 이력
6. 일일 점검·지원종료 PDF 리포트
7. 감사 로그
8. 프런트엔드 자동 테스트와 로그인 화면

### 실제 외부 환경 필요

1. 점검 전용 Linux 계정과 SSH 키를 생성해 EC2 3대에서 수집 실증
2. 실제 제조사·프로젝트의 EOL/EOSL 데이터를 공식 URL과 함께 입력
3. 소유자가 있는 Teams Workflow URL 연결
4. AWS 계정에서 Terraform plan 비용 확인 후 apply
5. 실제 도메인의 DNS 연결과 Caddy 인증서 발급
6. S3 백업 후 별도 DB에서 복구 훈련
7. 운영 상태를 일정 기간 측정해 가동률·수집 성공률 계산

### 제출 자료

1. 변경된 최종 PPTX와 DOCX
2. 실제 화면 캡처와 AWS 구성 캡처
3. 복구 훈련 기록
4. 최종 발표 대본과 시연 영상 또는 시연 순서

외부 실증을 하지 않은 항목은 완료로 표시하거나 발표에서 성공했다고 주장하지 않는다.
