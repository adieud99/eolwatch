# 운영 데이터 백업

관리 서버에서 Python 3와 Docker Compose로 실행합니다. PostgreSQL 데이터와 DB에 연결된 소스 ZIP을 함께 보관합니다.

```sh
python3 /opt/eolwatch/scripts/backup-runtime.py --compose-dir /opt/eolwatch --verify-restore
```

기본값은 `docker-compose.prod.yml`, `/opt/eolwatch/backups`, 완료된 백업 **최근 7개**입니다. 다른 구성을 쓰면 `--compose-file docker-compose.yml`, 경로를 바꾸면 `--backup-dir /별도/백업/경로`를 지정합니다. Docker 실행 파일은 `--docker-command /usr/bin/docker`로 지정할 수 있습니다.

## 보관 내용과 검증

- `database.dump`: 동일한 PostgreSQL 읽기 스냅샷에서 생성한 custom 형식 덤프. 모든 DB 테이블·스키마를 포함합니다.
- `uploads.zip`: 해당 스냅샷의 `analysis_uploads`가 참조하는 원본 ZIP. 파일 이름은 `SHA256.zip` 형식만 허용합니다. 원본 이름·프로젝트명·자산 연결은 DB에 남습니다.
- `manifest.json`: 두 파일의 SHA256·크기, 테이블별 행 수·내용 SHA256, 업로드별 SHA256·크기, 복원 검증 여부.
- `COMPLETE`: manifest 해시를 포함한 완료 표시. 파일 기록·검증 후 디렉터리 이름을 원자적으로 변경합니다.

백업 디렉터리는 `0700`, 내부 파일은 `0600`입니다. 실패한 실행의 임시 디렉터리는 삭제하고 이전 백업은 유지합니다. 보관 개수 정리는 새 백업이 완료된 뒤에만 실행하며, 이 스크립트가 같은 Compose 프로젝트용으로 만든 완료 백업만 삭제합니다. 알 수 없는 파일·디렉터리·심볼릭 링크는 삭제하지 않습니다.

`--verify-restore`는 같은 PostgreSQL 서버에 `eolwatch_verify_<고유값>` 임시 DB를 만들고 덤프를 복원합니다. 전체 테이블의 행 수·내용 해시와 ZIP 참조·원본 해시를 대조한 뒤 임시 DB를 삭제합니다. 운영 DB에 복원하는 옵션은 없습니다. 실패해도 임시 DB 삭제를 시도하며, 삭제 권한·연결에 문제가 있으면 정리할 DB 이름을 오류에 표시합니다.

DB 접속 정보는 컨테이너의 기존 환경을 사용합니다. `.env`, SSH 개인키, 토큰을 출력하거나 다른 서비스로 전송하지 않습니다. 덤프에는 사용자·인증 관련 DB 데이터가 포함되므로 백업 접근 권한을 제한해야 합니다.

## 매일 자동 실행

아래 명령을 **명시적으로 실행할 때만** 현재 사용자의 cron에 관리 서버 현지 시각 03:20 예약을 설치합니다. 기존 다른 cron 항목은 유지하고, 재실행하면 같은 프로젝트의 백업 항목만 갱신합니다.

```sh
python3 /opt/eolwatch/scripts/backup-runtime.py --compose-dir /opt/eolwatch --verify-restore --install-schedule
```

설치 명령은 백업을 즉시 실행하지 않습니다. 실행 결과는 `backups/cron.log`에 기록합니다. 해당 사용자가 Docker 실행 권한을 갖고 있고, cron 서비스가 동작하며, 서버 시간대가 의도한 시간대인지 확인합니다.

### 로컬 VM 적용 기록 — 2026-09-15

컨트롤러 `/opt/eolwatch`의 `docker-compose.yml` 구성에서 실제 백업과 임시 DB 복원이 통과했습니다. PostgreSQL 23개 테이블의 행 수·내용 해시, DB에 등록된 소스 ZIP 원본 해시가 일치했고, 검증용 임시 DB는 삭제됐습니다. 백업 위치는 `/opt/eolwatch/backups/eolwatch-runtime-20260915T144542Z-76c425a192bc`입니다.

복원 검증이 통과한 뒤 root cron에 매일 백업·복원 검증을 설치했습니다. 컨트롤러 시간대는 **Etc/UTC**이므로 **03:20 UTC = 12:20 한국 시각**에 실행합니다. cron 서비스는 `active`이며 기존 다른 항목의 해시는 설치 전후 동일합니다. 첫 예약 실행은 2026-09-16 03:20 UTC입니다. 파일·원본 해시와 설치된 전용 cron 블록은 `reports/runtime-backup-verification.json`에 기록했습니다.

## 장애 복구 범위

이 백업은 **DB와 원본 소스 ZIP**을 복구하는 자료입니다. 소스 코드·Compose 설정은 배포한 Git 커밋으로 준비하고, `.env`와 SSH 키·known_hosts는 별도로 안전하게 보관한 기존 파일을 사용합니다. 스캐너 캐시는 다시 생성할 수 있습니다. 워커의 원시 실행 로그 볼륨은 포함하지 않으며, 분석 결과 SBOM·Grype 보고서는 DB 덤프에 포함됩니다.

실제 장애 복구에서는 API·워커를 정지한 상태에서 새 DB와 새 업로드 볼륨에 복원한 뒤 연결 설정을 전환합니다. 덤프에는 `pg_restore`를 사용하고, ZIP은 manifest와 SHA256 검증 후 `64자리 소문자 16진수.zip` 이름의 일반 파일만 새 업로드 디렉터리에 복원합니다. 임의 경로·심볼릭 링크를 추출하는 일반 압축 해제 명령은 사용하지 않습니다. DB의 마이그레이션 버전과 배포 코드 버전을 맞춘 뒤 서비스를 시작합니다.

`--verify-restore` 통과는 임시 DB 복원과 저장 데이터의 일치 확인입니다. 실제 운영 연결 전환이나 외부 저장소 복제는 수행하지 않습니다. 이 명령으로 만든 백업은 같은 관리 서버에 보관되므로 서버·디스크 전체 장애에 대비한 별도 보관은 추가 운영 작업입니다.
