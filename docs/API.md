# API 사용 예시

대화형 명세는 서버 실행 후 <http://localhost:8000/docs>에서 확인한다.

## 자산 등록

```bash
curl -X POST http://localhost:8000/api/assets \
  -H 'Content-Type: application/json' \
  -d '{
    "asset_tag": "SRV-001",
    "name": "운영 웹 서버",
    "asset_type": "server",
    "manufacturer": "Example Vendor",
    "model": "Rack 2U",
    "support_end_date": "2026-12-31",
    "lifecycle_source_url": "https://example.com/support",
    "monitored": true
  }'
```

지원종료일을 입력하면 반드시 근거 URL도 입력해야 한다.

## SBOM 가져오기

```bash
curl -X POST 'http://localhost:8000/api/sboms/import?asset_id=1' \
  -H 'Content-Type: application/json' \
  --data-binary @samples/cyclonedx-example.json
```

현재 CycloneDX JSON 1.4~1.7을 지원한다. 같은 `serialNumber`와 문서 `version` 조합은 한 번만 저장된다.

## 조회

```bash
curl http://localhost:8000/api/dashboard/summary
curl http://localhost:8000/api/assets
curl http://localhost:8000/api/sboms
curl http://localhost:8000/api/sboms/1/components
```

## 고객사와 사이트

```bash
curl -X POST http://localhost:8000/api/customers \
  -H 'Content-Type: application/json' \
  -d '{"customer_code":"CUST-001","name":"시연 고객사"}'

curl -X POST http://localhost:8000/api/sites \
  -H 'Content-Type: application/json' \
  -d '{"customer_id":1,"site_code":"SEOUL-DC","name":"서울 전산실"}'
```

## 제품 릴리스와 영향 자산

SBOM을 가져오면 구성요소가 purl·CPE·공급사·이름·버전을 기준으로 제품 릴리스에 자동 연결된다.

```bash
curl 'http://localhost:8000/api/products?q=openssl'
curl http://localhost:8000/api/products/1/impact
```

제품 릴리스에 지원종료일을 입력하면 공식 근거 URL도 필요하다.

```bash
curl -X PATCH http://localhost:8000/api/products/1 \
  -H 'Content-Type: application/json' \
  -d '{"support_end_date":"2027-04-30","lifecycle_source_url":"https://vendor.example/lifecycle"}'
```

## SSH 인프라 점검

자산에 `ip_address`와 `ssh_username`을 등록하고 `.env` 또는 worker 컨테이너에 개인키·known_hosts 경로를 설정한다.

```bash
curl -X POST http://localhost:8000/api/checks/assets/1/run
curl http://localhost:8000/api/checks
curl http://localhost:8000/api/checks/1/result
```

성공한 점검에서 수집한 OS 패키지를 CycloneDX 1.7 SBOM으로 만들 수 있다.

```bash
curl -X POST http://localhost:8000/api/checks/1/sbom
```

## 유지보수 계약

```bash
curl -X POST http://localhost:8000/api/contracts \
  -H 'Content-Type: application/json' \
  -d '{
    "customer_id":1,
    "contract_no":"MA-2026-001",
    "provider":"유지보수 수행사",
    "start_date":"2026-01-01",
    "end_date":"2026-12-31",
    "annual_cost":12000000,
    "service_level":"24x7",
    "asset_ids":[1]
  }'
```
