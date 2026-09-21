# 취약 의존성 시연 프로젝트

검사 결과에 CVE가 반드시 나오도록 오래된 버전을 고정한 예제다. 실행하지 않는다.

| 폴더 | 언어 | 고정 버전 (알려진 CVE) |
|---|---|---|
| api | Python | Django 2.2, Flask 0.12.2, Jinja2 2.10, requests 2.19.1, PyYAML 5.1, urllib3 1.24.1, Pillow 6.2.0 |
| web | Node.js | lodash 4.17.15, minimist 1.2.0, axios 0.21.0, express 4.16.0, node-fetch 2.6.0 |
| batch | Java | log4j-core 2.14.1 (Log4Shell), jackson-databind 2.9.8, commons-collections 3.2.1 |

`개발 검사`에서 이 폴더를 ZIP으로 올리거나, `samples/vulnerable-demo/api/requirements.txt` 한 파일만 올려도 된다.
