# 운영·백업·장애 대응 절차

## 1. 매일 확인할 항목

- 실패한 수집 작업과 `failure_stage`
- 3회 이상 연속 실패한 자산
- EXPIRED·CRITICAL 자산과 제품 릴리스
- SBOM 품질 70점 미만 문서
- 실패한 알림과 백업 작업
- 서비스 EC2 디스크 사용률

## 2. 수집 실패 코드

| 단계 | 대표 코드 | 확인할 것 |
|---|---|---|
| CONNECT | TARGET_NOT_CONFIGURED | 자산 IP와 SSH 계정 입력 여부 |
| CONNECT | TIMEOUTERROR, SSHException | 라우팅, 보안그룹, sshd 상태 |
| AUTH | KEY_NOT_FOUND | 키 파일 마운트와 파일 권한 |
| AUTH | AUTHENTICATION_FAILED | 공개키 등록, 계정 잠금 여부 |
| COMMAND | `*_EXIT_n` | 명령 설치 여부와 점검 계정 권한 |
| PARSE | INVALID_CPU 등 | OS별 명령 출력 차이 |

실패한 수집은 정상 점검으로 처리하지 않는다. 원인을 수정한 뒤 자산 화면에서 수동 점검을 실행하고, 성공 여부를 점검 이력에서 확인한다.

## 3. 백업

운영 EC2에서 다음 환경변수를 지정한 뒤 매일 한 번 실행한다.

```bash
export POSTGRES_USER=eolwatch
export POSTGRES_DB=eolwatch
export BACKUP_BUCKET=eolwatch-backup-example
./scripts/backup.sh
```

스크립트는 PostgreSQL 논리 백업을 gzip으로 압축하고 S3의 `postgres/` 경로에 AES256 서버 측 암호화로 업로드한다. Terraform 수명주기 정책이 7일이 지난 백업을 삭제한다.

## 4. 복구 훈련

운영 DB에 바로 덮어쓰지 않고 별도의 검증 환경에서 수행한다.

```bash
export POSTGRES_USER=eolwatch
export POSTGRES_DB=eolwatch_restore_test
./scripts/restore.sh s3://버킷/postgres/eolwatch-YYYYMMDDTHHMMSSZ.sql.gz
```

복구 후 다음을 확인한다.

1. 고객사·사이트·자산 수
2. 자산과 제품 릴리스 연결 수
3. SBOM 문서와 구성요소·의존관계 수
4. 최근 점검 결과
5. 대시보드 위험도 집계

복구 일시, 백업 파일, 소요 시간, 검증 결과를 운영 기록에 남긴다.

## 5. 컨테이너 장애

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs --tail=200 api worker db caddy
docker compose -f docker-compose.prod.yml restart api
```

API 재기동 전에 DB가 `healthy`인지 확인한다. 마이그레이션 실패가 보이면 애플리케이션을 계속 재기동하지 말고 `alembic current`와 실패한 revision을 확인한다.

## 6. 발표 전 복구 실증 기록

| 항목 | 기록 값 |
|---|---|
| 훈련 일시 | 미실시 |
| 사용 백업 | 미정 |
| 복구 소요 시간 | 미측정 |
| 데이터 검증 | 미실시 |
| 발견한 문제 | 미작성 |
| 개선 결과 | 미작성 |

이 표는 실제 복구 훈련 후 사실대로 갱신한다. 수행하지 않은 상태에서 복구 성공으로 발표하지 않는다.
