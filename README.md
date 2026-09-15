# EOLWatch

EOLWatch는 인프라 통합 유지관리 업무에서 서버·스토리지·네트워크 장비와 그 위에서 동작하는 인프라 소프트웨어의 지원종료 위험을 한곳에서 추적하는 프로젝트입니다. 시스원의 인프라 구축·운영·유지관리 사업과 연결되는 주제로, 기존 1차 기획의 하드웨어 EOSL 관리에 CycloneDX 기반 SBOM(Software Bill of Materials)을 적용했습니다.

이 프로젝트는 학교 파이널 프로젝트이며 시스원의 공식 제품이나 실제 내부 시스템을 재현한 것은 아닙니다. 공개된 사업 영역과 일반적인 인프라 유지관리 업무를 바탕으로 기획했습니다.

## 무엇을 관리하나

- 물리·가상·클라우드 자산의 제조사 지원종료일과 유지보수 근거
- 고객사·사이트·유지보수 계약과 자산 연결
- 자산에 설치된 운영체제·펌웨어·하이퍼바이저·DBMS·백업/보안 에이전트
- CycloneDX JSON SBOM의 구성요소, 식별자, 라이선스, 의존관계
- 관리자·조회자 권한과 변경 감사 로그
- SBOM 버전 비교, OSV 취약점 조회와 VEX 상태
- 자산 CSV 일괄 등록, PDF 보고서, Teams Workflows 위험 건수 알림
- 읽기 전용 SSH 일일 점검과 OS 패키지 기반 CycloneDX SBOM 생성
- 하드웨어와 소프트웨어를 합산한 위험도 및 SBOM 품질
- 향후 SSH 상태 수집, 취약점/VEX, PDF 리포트, Teams 알림으로 확장 가능한 구조

SBOM은 소프트웨어 구성명세서입니다. 물리 자산 자체는 SBOM이라고 부르지 않고 자산/HBOM 영역으로 구분합니다. EOLWatch에서는 인프라 자산을 중심에 놓고, SBOM을 해당 자산에서 운영되는 소프트웨어를 식별하는 자료로 사용합니다.

## 로컬 실행

Docker가 있으면 다음 명령으로 API, PostgreSQL, 웹 화면을 함께 실행할 수 있습니다.

```bash
docker compose up --build
docker compose exec api python -m app.seed
```

- 웹 화면: <http://localhost:8080>
- API 문서: <http://localhost:8000/docs>
- 상태 확인: <http://localhost:8000/health>

로컬 초기 관리자 계정은 `admin` / `Eolwatch!2026`이다. 실제 배포에서는 `ADMIN_PASSWORD`와 `JWT_SECRET`을 반드시 별도 비밀값으로 설정한다.

Docker 없이 백엔드만 확인할 때는 Python 3.9 이상에서 다음과 같이 실행합니다. 이때 기본 DB는 `backend/eolwatch.db`입니다.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

샘플 SBOM은 `samples/cyclonedx-example.json`에 있습니다.

```bash
curl -X POST http://localhost:8000/api/sboms/import \
  -H 'Content-Type: application/json' \
  --data-binary @samples/cyclonedx-example.json
```

DB 구조 변경은 Alembic으로 관리하며 API 컨테이너 시작 시 자동으로 최신 revision을 적용합니다. 로컬 Python 실행에서는 다음 명령으로 직접 적용할 수 있습니다.

```bash
cd backend
alembic upgrade head
```

## 문서

- [SBOM 반영 2차 기획](docs/PROJECT_PLAN_V2.md)
- [시스템 아키텍처](docs/ARCHITECTURE.md)
- [전체 ERD와 데이터 설계](docs/DATA_MODEL.md)
- [기술 스택과 선정 이유](docs/TECH_STACK.md)
- [API 사용 예시](docs/API.md)
- [배포 절차](docs/DEPLOYMENT.md)
- [운영·백업·복구 절차](docs/OPERATIONS.md)
- [현재 구현 현황](docs/IMPLEMENTATION_STATUS.md)
- [다음 작업 재개 가이드](docs/NEXT_SESSION.md)
- [AWS 실제 배포 기록](docs/AWS_DEPLOYMENT_RECORD.md)

초기 PPTX와 DOCX는 원본 기획 자료로 보존했습니다. 구현 기준은 2차 기획 문서입니다.
