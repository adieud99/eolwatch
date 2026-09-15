# AWS 실제 배포 기록

기준일: 2026-09-15

## 생성된 환경

- 리전: 서울 `ap-northeast-2`
- 서비스 EC2: `i-0c8159d287eccf69e` (`t4g.small`)
- 서비스 Elastic IP: `43.202.102.80`
- 점검 대상 EC2: `i-081ad88765be235ae`, `i-04dbc97fda70da8f8`, `i-034c4b7bad3fb40d1`
- 점검 대상 사설 IP: `10.70.10.164`, `10.70.10.114`, `10.70.10.28`
- 백업 버킷: `eolwatch-backup-20260915024748650000000001`
- 임시 HTTPS 이름: `43-202-102-80.sslip.io`

Terraform은 관리 리소스 24개와 데이터 소스 2개를 추적한다. S3 버킷은 공개 접근 차단, AES-256 서버 측 암호화, `postgres/` 경로 7일 만료 정책을 적용했다. 서비스 서버는 80·443만 공개하며 운영 접속에는 SSH 포트를 열지 않고 SSM을 사용한다. 점검 대상의 SSH 포트는 서비스 보안그룹에서만 접근할 수 있다.

서비스 서버 역할만 백업 버킷과 `/eolwatch/production/*` SecureString을 읽을 수 있다. 점검 대상 3대는 별도 IAM 역할로 분리해 SSM 관리 권한만 부여했다. PostgreSQL, JWT, 관리자 암호는 Terraform 상태와 Git에 넣지 않고 Parameter Store에서 생성해 서비스 서버의 권한 `0600` 환경 파일에 주입했다.

## 현재 검증 상태

- 네 EC2 인스턴스가 AWS 상태 검사를 통과했다.
- 네 EC2 인스턴스가 SSM Online 상태다.
- Elastic IP를 가리키는 임시 DNS 조회가 성공했다.
- 운영 소스 묶음 108개 파일에서 `.git`, `.venv`, `node_modules`, 빌드 결과, Terraform 상태, 환경 파일, SSH 키와 `known_hosts` 제외를 확인했다.
- 소스 묶음 SHA-256 `c775ee67b54f5708302de84012198ed0789bc37093367519b4e09bbe292c67e9`를 업로드 전과 서버 다운로드 후 모두 확인했다.
- Docker 25.0.14, Compose 5.5.0, Buildx 0.37.1을 설치했으며 Compose와 Buildx 바이너리는 공식 SHA-256으로 검증했다.
- 운영 컨테이너 `db`, `api`, `worker`, `web`, `caddy`를 빌드하고 기동했다.
- `https://43-202-102-80.sslip.io/health`가 HTTP 200과 `{"status":"ok"}`를 반환한다.
- Let's Encrypt 인증서, HSTS, `nosniff`, 프레임 차단 헤더를 확인했다.
- 수집 공개키를 대상 3대의 `eolwatch` 계정에 설치하고 서비스 서버에서 키 인증 연결을 확인했다.

## 남은 검증 단계

1. 수동 점검 API에도 읽기 전용 SSH 키 볼륨을 연결한 운영 Compose 파일을 배포한다.
2. 대상 EC2 3대의 애플리케이션 점검과 SBOM 생성을 확인한다.
3. PostgreSQL 백업을 S3에 올리고 별도 임시 DB로 복구 검증한다.
4. Teams Workflow URL을 제공받으면 실제 알림 전송을 확인한다.

현재 서비스와 HTTPS는 정상 동작한다. 수동 점검 API의 SSH 키 마운트 보완 파일은 자동 승인 검토에서 외부 전송이 차단돼 별도 사용자 승인을 기다리고 있다.

Terraform 상태 파일에는 인프라 식별정보가 들어 있으므로 Git에 커밋하지 않는다.
