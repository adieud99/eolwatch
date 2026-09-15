# 배포 절차

## 1. 로컬 개발 실행

```bash
cp .env.example .env
docker compose up --build -d
docker compose exec api python -m app.seed
```

접속 주소:

- 대시보드: <http://localhost:8080>
- API 문서: <http://localhost:8000/docs>
- 상태 확인: <http://localhost:8000/health>

종료할 때 데이터 볼륨을 보존하려면 다음 명령만 사용한다.

```bash
docker compose down
```

`docker compose down -v`는 PostgreSQL 볼륨까지 삭제하므로 초기화가 필요한 경우에만 사용한다.

## 2. AWS 인프라 준비

AWS 자격증명을 구성한 뒤 Terraform을 실행한다. `plan` 결과에 EC2와 S3 비용이 발생할 수 있으므로 리소스 수와 리전을 확인한 후 적용한다.

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform fmt -check
terraform validate
terraform plan -out=eolwatch.tfplan
terraform apply eolwatch.tfplan
```

생성되는 주요 자원:

- EOLWatch 서비스 EC2 1대
- 점검 대상 EC2 최대 3대
- 80·443만 공개한 서비스 보안그룹
- 서비스 보안그룹에서 오는 22번만 허용한 대상 보안그룹
- SSM 접속용 IAM 역할
- 암호화·공개 차단·7일 만료 정책이 적용된 S3 백업 버킷
- 서비스 고정 IP용 Elastic IP

Terraform은 실제로 리소스를 생성한다. 2026-09-15 서울 리전에 서비스 EC2 1대와 점검 대상 EC2 3대를 포함한 20개 리소스를 적용했다. 현재 식별정보와 검증 결과는 `AWS_DEPLOYMENT_RECORD.md`에 기록한다.

## 3. DNS와 운영 환경변수

Terraform 출력의 `service_public_ip`를 도메인의 A 레코드에 연결한다. EC2의 `/opt/eolwatch/.env`에는 다음 값을 설정한다.

```dotenv
DOMAIN=eolwatch.example.com
POSTGRES_DB=eolwatch
POSTGRES_USER=eolwatch
POSTGRES_PASSWORD=충분히_긴_URL안전_비밀번호
COLLECTION_HOUR=8
COLLECTION_MINUTE=30
BACKUP_BUCKET=terraform-output-bucket-name
JWT_SECRET=32바이트_이상의_무작위_비밀값
ADMIN_USERNAME=admin
ADMIN_PASSWORD=충분히_긴_관리자_비밀번호
PUBLIC_BASE_URL=https://eolwatch.example.com
TEAMS_WEBHOOK_URL=
```

실제 비밀번호와 SSH 개인키는 저장소에 커밋하지 않는다. 운영 단계에서는 SSM Parameter Store 값을 배포 시 환경 파일 또는 Docker Secret으로 주입한다.

## 4. 운영 Compose 배포

```bash
cd /opt/eolwatch
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
curl -fsS https://eolwatch.example.com/health
```

운영 Compose에서는 Caddy만 80·443을 호스트에 공개한다. FastAPI, PostgreSQL, 웹 Nginx는 Docker 내부 네트워크에서만 접근한다. API 컨테이너가 시작될 때 `alembic upgrade head`를 먼저 실행한다.

## 5. SSH 점검 계정

대상 Linux 서버마다 전용 계정을 만든 뒤 읽기 명령만 허용한다. 시연 환경에서도 root 로그인과 비밀번호 인증은 사용하지 않는다.

수집 명령:

- `/proc/uptime` 읽기
- `top`, `free`에 해당하는 CPU·메모리 정보
- `df -P`
- `ps -eo`
- `dpkg-query -W` 또는 `rpm -qa`

운영자가 대상 서버의 호스트 키 지문을 확인한 후 `secrets/known_hosts`에 넣는다. `SSH_STRICT_HOST_KEY=true`를 유지한다.

## 6. 배포 확인

```bash
docker compose -f docker-compose.prod.yml exec api alembic current
docker compose -f docker-compose.prod.yml exec api python -m app.seed
docker compose -f docker-compose.prod.yml logs --tail=100 api worker
```

확인 항목:

1. HTTPS 인증서가 정상 발급된다.
2. `/health`가 `{"status":"ok"}`를 반환한다.
3. 고객사·사이트·자산 등록이 가능하다.
4. CycloneDX 샘플 파일이 공식 스키마 검증을 통과한다.
5. SSH 정보가 없는 자산의 점검은 실패 원인을 기록한다.
6. 시연용 대상 서버 점검에서 CPU·메모리·디스크가 저장된다.
7. API와 DB 포트가 외부에서 열려 있지 않다.
