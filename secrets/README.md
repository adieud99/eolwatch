# 로컬 비밀정보 디렉터리

SSH 점검을 실행하려면 다음 파일을 이 디렉터리에 둔다.

- `eolwatch_ssh_key`: 점검 전용 SSH 개인키, 권한 `600`
- `known_hosts`: `ssh-keyscan` 결과를 운영자가 확인한 뒤 등록한 호스트 키

실제 키 파일은 Git에 커밋하지 않는다. 운영 배포에서는 파일 대신 AWS Systems Manager Parameter Store를 사용한다.
