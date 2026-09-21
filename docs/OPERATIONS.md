# 운영·백업·장애 대응 절차

## 1. 매일 확인할 항목

- 실패한 SSH 점검·검사 작업과 `failure_stage`·오류 코드 (개요의 최근 24시간 실패 점검 수)
- 3회 이상 연속 실패한 서버
- 서버 정보 수집에서 건강도 CRITICAL로 판정된 서버
- SBOM 품질 70점 미만 문서
- 실패한 백업 작업
- 서비스 서버 디스크 사용률

## 2. 수집 실패 코드

| 단계 | 대표 코드 | 확인할 것 |
|---|---|---|
| CONNECT | TARGET_NOT_CONFIGURED | 서버 IP와 SSH 계정 입력 여부 |
| CONNECT | TIMEOUTERROR, SSHException | 라우팅, 보안그룹, sshd 상태 |
| AUTH | KEY_NOT_FOUND | 키 파일 마운트와 파일 권한 |
| AUTH | AUTHENTICATION_FAILED | 공개키 등록, 계정 잠금 여부 |
| COMMAND | `*_EXIT_n` | 명령 설치 여부와 점검 계정 권한 |
| PARSE | INVALID_CPU 등 | OS별 명령 출력 차이 |

실패한 수집은 정상 점검으로 처리하지 않는다. 원인을 수정한 뒤 `인프라 검사`에서 `SSH 점검`을 다시 실행하고, 성공 여부를 서버 정보 수집 이력에서 확인한다. 취약점 검사 작업의 실패는 `재시도`로 새 작업을 만든다.

## 3. 백업과 복구

현재 기준 절차는 [운영 백업](BACKUP_OPERATIONS.md)이다. 관리 VM에서 `scripts/backup-runtime.py --verify-restore`로 PostgreSQL과 업로드 ZIP을 함께 보관하고, 임시 DB 복원·내용 해시 대조까지 확인한다. 보관 개수 관리와 정기 실행도 같은 문서를 따른다.

`scripts/backup.sh`·`scripts/restore.sh`의 S3 업로드 방식은 AWS 운영을 전제한 이전 절차다. 현재 로컬 시연 구성에서는 사용하지 않는다.

## 4. 컨테이너 장애

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs --tail=200 api worker db caddy
docker compose -f docker-compose.prod.yml restart api
```

API 재기동 전에 DB가 `healthy`인지 확인한다. 마이그레이션 실패가 보이면 애플리케이션을 계속 재기동하지 말고 `alembic current`와 실패한 revision을 확인한다.
