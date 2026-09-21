# EOLWatch 데이터 모델

기준일: 2026-09-15. [실제 모델](../backend/app/models.py)과 Alembic **`e5a294dc13b7`** 기준이다. 도면은 구현된 테이블·주요 컬럼을 발췌했으며 미래 설계 컬럼을 섞지 않는다. 현재 애플리케이션 테이블은 20개다. 새 조치 이력 확장의 배포·검증 상태는 [구현 현황](IMPLEMENTATION_STATUS.md)을 따른다.

## 1. 자산·분석·취약점 핵심 ERD

```mermaid
erDiagram
    assets ||--o{ analysis_jobs : requested_for
    assets o|--o{ sbom_documents : associated_with
    sbom_documents ||--o{ analysis_runs : analyzed_by
    sbom_documents ||--o{ components : contains
    sbom_documents ||--o{ dependency_edges : describes
    analysis_runs o|--o{ analysis_jobs : produces_result
    analysis_jobs o|--o{ analysis_jobs : retry_of
    components ||--o{ component_vulnerabilities : detected_in
    vulnerabilities ||--o{ component_vulnerabilities : identifies
    analysis_runs o|--o{ component_vulnerabilities : latest_link_source
    component_vulnerabilities ||--o{ vulnerability_actions : reviewed_by
    users o|--o{ component_vulnerabilities : assigned_to
    users o|--o{ vulnerability_actions : acted_by
    analysis_runs o|--o{ vulnerability_actions : attached_evidence

    assets {
        int id PK
        string asset_tag UK
        string name
        string asset_type
        string ip_address
        int ssh_port
        string ssh_username
        boolean monitored
    }
    analysis_jobs {
        int id PK
        int asset_id FK
        int active_asset_id UK
        json asset_snapshot
        string status
        string worker_token
        datetime heartbeat_at
        datetime requested_at
        datetime started_at
        datetime finished_at
        string error_code
        text error_message
        int analysis_run_id FK
        int retry_of_id FK
    }
    sbom_documents {
        int id PK
        int asset_id FK
        int software_product_id FK
        int collection_job_id FK
        string serial_number
        string bom_format
        string spec_version
        int document_version
        datetime generated_at
        datetime imported_at
        int component_count
        int dependency_count
        float quality_score
        json quality_details
        json raw_document
    }
    analysis_runs {
        int id PK
        int sbom_id FK
        string report_sha256 UK
        string sbom_sha256
        string scanner
        string scanner_version
        string generator
        string scan_scope
        int match_count
        int cve_count
        int link_count
        int ignored_non_cve
        json database_info
        json raw_report
        datetime imported_at
    }
    components {
        int id PK
        int sbom_id FK
        int product_release_id FK
        string bom_ref
        string component_type
        string name
        string version
        string purl
        string cpe
        string supplier
        json licenses
        json hashes
        date support_end_date
        text lifecycle_source_url
    }
    dependency_edges {
        int id PK
        int sbom_id FK
        string source_ref
        string target_ref
    }
    vulnerabilities {
        int id PK
        string osv_id UK
        string severity
        text summary
        text details
        json aliases
        json references
        datetime published_at
        datetime modified_at
    }
    component_vulnerabilities {
        int id PK
        int component_id FK
        int vulnerability_id FK
        int analysis_run_id FK
        string finding_source
        string finding_severity
        string fixed_version
        json fixed_versions
        string vex_status
        int review_revision
        int assignee_id FK
        date due_date
        string justification
        string response
        text detail
        datetime updated_at
    }
    vulnerability_actions {
        int id PK
        int link_id FK
        int actor_user_id FK
        string actor_username
        string from_status
        string to_status
        text detail
        json before_state
        json after_state
        int evidence_analysis_run_id FK
        json evidence_snapshot
        datetime created_at
    }
```

- `analysis_jobs.asset_snapshot`에 자산 ID·이름·태그·IP·SSH 포트·계정·`scan_scope`를 저장한다. 개인키와 로그인 토큰은 저장하지 않는다. `scan_scope`는 작업 테이블의 별도 컬럼이 아니라 이 JSON과 분석 이력 컬럼에 있다.
- `active_asset_id`는 **nullable 고유 컬럼이며 FK는 아니다.** 대기·실행 중에만 자산 ID를 넣어 같은 자산의 동시 분석을 막는다. 완료·실패 시 NULL로 비운다.
- `worker_token`은 실행 작업의 소유권 확인 값이다. API 응답이나 보고서에는 노출하지 않는다.
- 한 SBOM에 여러 분석 이력이 연결될 수 있다. 하나의 분석 이력에 연결되는 작업도 DB 차원에서 하나로 제한하지 않는다.
- `dependency_edges`는 SBOM 내부의 `source_ref`·`target_ref` 문자열을 저장한다. 구성요소 ID FK 두 개를 가진 구조가 아니다.
- `vulnerabilities.osv_id`는 기존 이름을 유지한다. Grype 반입 경로에서는 `CVE-...`를 저장하고 CVE가 아닌 별칭은 `aliases`로 보존한다.

## 2. 원본과 조회용 연결의 역할

| 데이터 | 용도 |
|---|---|
| `sbom_documents.raw_document` | 해당 시점의 SPDX 또는 CycloneDX 원본 |
| `analysis_runs.raw_report` | 해당 분석의 Grype 원본 |
| `components`, `component_vulnerabilities` | 구성요소·CVE 조회, 수동 VEX·조치 정보 |
| `analysis_runs.sbom_sha256` | 정규화한 SBOM JSON의 SHA-256 |
| `analysis_runs.report_sha256` | 이름과 달리 `asset_id + sbom + report` 묶음의 SHA-256. 동일 반입 식별에도 사용 |
| 비교·보고서 | 별도 결과 테이블 없이 원본에서 읽기 전용으로 계산 |
| `vulnerability_actions` | 조치 시점의 작성자·전후 상태·담당자/기한·선택한 재분석 근거 스냅샷 |

전후 비교는 변경 가능한 VEX 연결 값을 과거 탐지 근거로 사용하지 않는다. 같은 자산·범위·순서를 확인하고 원본 보고서의 CVE와 SBOM 설치 목록을 대조한다. 보고서 생성 시에는 원본 내용과 저장된 해시도 검증한다. 해시는 내용 일치 검사이며 외부 작성자의 서명은 아니다.

비교의 한 행은 **버전을 제외한 구성요소 식별자 + CVE**다. 생태계·네임스페이스·배포판·아키텍처·하위 경로와 동시에 설치된 버전 집합을 보존한다. `before_versions`·`after_versions`는 해당 식별자의 설치 목록이며, `NO_LONGER_DETECTED`를 자동 `FIXED`로 저장하지 않는다.

현재 조치 상태는 `component_vulnerabilities`에 있고 변경 이력은 `vulnerability_actions`에 추가한다. 클라이언트의 `expected_revision`과 현재 `review_revision`이 같을 때만 갱신한다. 상태 갱신·이력·`VULNERABILITY_ACTION` 감사 로그는 같은 트랜잭션이다. `actor_username`, `before_state`, `after_state`, `evidence_snapshot`은 기록 당시 값을 보존한다. 외부 비교 근거가 없는 수동 기록과 비교 첨부 수동 결정을 구분한다.

작성자·근거 분석 FK는 삭제 시 NULL이 될 수 있으나 스냅샷은 남는다. 해당 CVE 연결 자체를 삭제하면 `link_id`의 CASCADE가 적용되므로 이 테이블을 변경 불가능한 외부 감사 저장소로 설명하지 않는다.

요청·이력의 사용 기준은 [조치 이력 안내](VULNERABILITY_ACTIONS.md)에 정리한다. 기존 OSV 재조회는 Grype 분석에 연결된 원본 근거와 조치 상태를 덮어쓰지 않는다.

## 3. 고객·자산·운영 보조 ERD

```mermaid
erDiagram
    customers ||--o{ sites : owns
    sites o|--o{ assets : located_at
    product_releases o|--o{ assets : model_release
    assets ||--o{ deployments : hosts
    product_releases ||--o{ deployments : installed_release
    product_releases o|--o{ components : normalized_release
    product_releases o|--o{ sbom_documents : product_bom
    customers ||--o{ contracts : contracts
    contracts ||--o{ contract_assets : covers
    assets ||--o{ contract_assets : covered_by
    assets ||--o{ collection_jobs : checked_by
    collection_jobs ||--o| check_results : produces
    collection_jobs o|--o{ sbom_documents : collected_for
    users o|--o{ audit_logs : performs
```

| 테이블 | 주요 실제 컬럼·역할 |
|---|---|
| `customers` | `customer_code`, `name`, `status`, `created_at` |
| `sites` | `customer_id`, `site_code`, `name`, `address`, `timezone` |
| `product_releases` | `product_type`, `vendor`, `name`, `version`, `purl`, `cpe`, EOL·지원·보안지원 종료일, 근거 URL·확인 시각 |
| `assets` 추가 컬럼 | 선택적 `site_id`, `model_release_id`, 제조사·모델·일련번호·도입일·지원종료일·근거 URL. 기존 `site` 문자열도 유지 |
| `deployments` | `asset_id`, `software_product_id`, `environment`, `discovered_at`. 제품 FK는 `product_releases.id` |
| `contracts`, `contract_assets` | 고객·계약·기간·금액·서비스 수준과 대상 자산 연결 |
| `collection_jobs` | 자산·트리거·상태·실패 단계/코드/메시지·시작/종료·재시도 횟수 |
| `check_results` | `collection_job_id`, CPU·메모리·디스크·가동시간·상태, 상세 JSON·`raw_metrics` |
| `users` | `username`, `password_hash`, `role`, `active`, 생성·마지막 로그인 시각 |
| `audit_logs` | `user_id`, `username`, `action`, `method`, `path`, `status_code`, `ip_address`, `created_at` |
| `notification_deliveries` | 채널·이벤트·성공/실패·응답 코드·오류·수신처 표시명·요약 JSON·생성 시각 |

일반 감사 로그는 로그인과 성공한 변경 요청의 사용자·경로·결과를 남긴다. 조치 변경의 전후 스냅샷은 `vulnerability_actions`에 따로 보존하며 일반 감사 로그가 모든 데이터의 변경 전후 복사본을 담는 것은 아니다. 개별 분석 작업의 `requested_by` FK나 보고서를 저장하는 `REPORT_HISTORY` 테이블은 현재 없다.

## 4. 무결성과 상태

| 제약 | 실제 기준 |
|---|---|
| 자산·계정·고객·계약 식별 | `asset_tag`, `username`, `customer_code`, `contract_no` 각각 유일 |
| 사이트 | `(customer_id, site_code)` 유일 |
| 제품 릴리스 | `(product_type, vendor, name, version)` 및 각각의 purl·CPE 고유 제약/인덱스 |
| 배포 | `(asset_id, software_product_id)` 유일. `environment`는 고유 키에 포함하지 않음 |
| SBOM | `(serial_number, document_version)` 유일 |
| 구성요소 | `(sbom_id, bom_ref)` 유일 |
| 의존관계 | `(sbom_id, source_ref, target_ref)` 유일 |
| CVE 연결 | `(component_id, vulnerability_id)` 유일 |
| 점검 결과 | 한 `collection_job_id`당 최대 한 행 |
| 분석 요청 | 활성 작업에 한해 자산별 한 행. 재시도는 새 ID와 이전 작업 FK 사용 |

SBOM의 자산·제품 FK는 모두 nullable이다. 일반 반입은 자산 없는 문서도 저장할 수 있지만 분석 묶음 반입·웹 분석·조치 비교는 자산을 요구한다. EOL 근거 URL 등 입력 규칙은 API 스키마·서비스에서 검사하며 모두 DB CHECK 제약인 것은 아니다.

웹 분석 상태는 `QUEUED → COLLECTING → SCANNING → IMPORTING → SUCCESS`, 실패 시 `FAILED`다. VEX 수정 API는 `AFFECTED`, `NOT_AFFECTED`, `FIXED`, `UNDER_INVESTIGATION`을 받는다. 자산 유형은 `server`, `storage`, `network`, `security`, `vm`, `cloud`, `other` 소문자 값이다.

주요 FK·식별·상태·검색 컬럼에 인덱스가 있다. 미래의 복합 인덱스나 보존 기간을 이미 구현한 것으로 표시하지 않는다. JSON 원본은 SQLAlchemy `JSON` 컬럼으로 정의돼 있으며 JSONB 전용 설계가 아니다.

## 5. 마이그레이션과 보존

```text
3f012f421ca0  자산·제품·SBOM·점검 기본 구조
  → 91c6d6d4a2f1  인증·취약점·운영 기록
  → 7c61b9af20d4  수정 버전 정보
  → c4d62a8170b3  분석 원본·도구 정보와 CVE 연결 근거
  → d8a671ec54f2  웹 분석 작업·소유권·재시도
  → e5a294dc13b7  담당자·기한·조치 버전과 변경/근거 스냅샷
```

API 컨테이너 시작 시 `alembic upgrade head`를 적용한다. 비교·PDF·JSON 보고서는 기존 원본을 조회하므로 새 결과 테이블을 추가하지 않았다. 운영 DB의 downgrade·초기화는 평상시 갱신 절차가 아니다.

원본과 과거 이력을 보관하지만 자동 보존 기간·논리 삭제·외부 변경 방지 저장소가 모두 구현된 것은 아니다. 자산 삭제 API는 실제 삭제이며 DB의 `CASCADE`·`SET NULL` 관계가 적용될 수 있다. 시연 이력을 보존할 때는 자산·볼륨을 삭제하지 않고 DB와 필요한 원본을 백업한다.

실제 예시는 자산 #1 → 작업 #2/#3 → 분석 #3/#4 → SBOM #12/#13이다. [조치 검증](archive/REMEDIATION_VERIFICATION_2026-09-15.md)과 [보고서 검증](archive/COMPARISON_REPORT_VERIFICATION_2026-09-15.md)에 원본·화면 근거가 있다.
