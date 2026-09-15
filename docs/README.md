# EOLWatch 설계 문서

다음 순서로 읽으면 프로젝트 전체 구조를 파악할 수 있다.

1. [2차 기획안](PROJECT_PLAN_V2.md) — 문제, 사용자, 범위, 완료 기준
2. [시스템 아키텍처](ARCHITECTURE.md) — 시스템·배포·수집·SBOM 흐름
3. [전체 ERD](DATA_MODEL.md) — 테이블, 관계, 제약조건, 인덱스
4. [기술 스택](TECH_STACK.md) — 선정 기술, 이유, 제외 기술, 구현 순서
5. [API 사용 예시](API.md) — 현재 구현된 API 호출 방법
6. [배포 절차](DEPLOYMENT.md) — 로컬·AWS·운영 Compose 배포
7. [운영 절차](OPERATIONS.md) — 점검 실패·백업·복구·장애 대응
8. [구현 현황](IMPLEMENTATION_STATUS.md) — 완료·검증·남은 작업
9. [AWS 실제 배포 기록](AWS_DEPLOYMENT_RECORD.md) — 생성 리소스와 배치 검증 상태

문서의 Mermaid 도면은 GitHub에서 바로 렌더링된다. 발표 자료에 사용할 때 GitHub 미리보기 또는 Mermaid Live Editor에서 SVG로 내보내면 확대해도 깨지지 않는다.

## 설계 기준 상태

| 문서 | 용도 | 기준 |
|---|---|---|
| 1차 DOCX/PPTX | 주제 선정 당시 자료 | 원본 보존 |
| PROJECT_PLAN_V2 | 수정된 범위와 일정 | 최신 기획 기준 |
| ARCHITECTURE | 최종 시스템 목표 | 구현 시 계속 갱신 |
| DATA_MODEL | 최종 목표 ERD | 마이그레이션 기준 |
| TECH_STACK | 기술 선택 | 발표와 구현 기준 |
