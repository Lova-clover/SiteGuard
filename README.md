# SiteGuard

공개 URL 하나로 웹사이트의 기본 보안 구성을 점검하고, 점수와 증거, 수정 가이드를 함께 제공하는 패시브 웹 보안 스캐너입니다.

SiteGuard는 “공격하는 도구”가 아니라 “배포 전에 놓치기 쉬운 보안 기본기를 빠르게 점검하는 도구”를 목표로 만들었습니다.  
HTTPS, TLS, 보안 헤더, 쿠키 속성, 리다이렉트, 혼합 콘텐츠 같은 항목을 읽기 전용으로 분석하고, 결과를 사람이 바로 이해하고 고칠 수 있는 형태로 정리해 보여줍니다.

## 왜 만들었나

AI 기반 개발과 바이브 코딩이 빨라질수록, 기능은 빠르게 나오지만 보안 기본 설정은 자주 빠집니다.

예를 들면 이런 문제들입니다.

- HTTP에서 HTTPS로 강제되지 않는 진입점
- 빠져 있는 HSTS, CSP, Referrer-Policy
- `Secure`, `HttpOnly`, `SameSite`가 없는 세션 쿠키
- 기술 스택 정보가 그대로 노출되는 응답 헤더
- HTTPS 페이지 안에 남아 있는 HTTP 리소스 참조

이 프로젝트는 “전문 보안 솔루션을 대체”하려는 것이 아니라, 배포 직전 누구나 한 번 돌려볼 수 있는 공개 보안 상태 점검기를 만드는 데 초점을 두고 있습니다.

## 핵심 기능

- 공개 URL 입력 한 번으로 보안 상태를 분석
- 보안 점수와 등급, 위험도 요약 제공
- 리다이렉트 체인, 응답 헤더, TLS 정보, 쿠키 플래그 등 증거 기반 리포트 제공
- 우선순위가 높은 문제부터 정렬된 Findings 제공
- 각 문제에 대해 왜 위험한지, 무엇을 고쳐야 하는지, 예시 설정 코드까지 제공
- JSON / Markdown 내보내기 지원
- 최근 검사 URL 기록 및 재실행 지원

## 어떤 항목을 점검하나

SiteGuard는 현재 다음 범위를 중심으로 점검합니다.

- HTTPS 지원 여부
- HTTP -> HTTPS 리다이렉트
- TLS 인증서 상태
- HSTS
- Content-Security-Policy
- 클릭재킹 방어 (`X-Frame-Options`, `frame-ancestors`)
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- 쿠키 보안 속성 (`Secure`, `HttpOnly`, `SameSite`)
- 명백한 CORS 오설정
- 기술 스택 노출 헤더
- 혼합 콘텐츠 신호
- 안전하지 않은 로그인 폼 전송 신호

## 이 도구가 하지 않는 것

이 프로젝트는 의도적으로 패시브 검사만 수행합니다.

- 브루트포스, 퍼징, 공격 페이로드 전송을 하지 않습니다.
- SQL Injection, XSS, IDOR, 권한 우회 같은 취약점을 “확정”하지 않습니다.
- 로그인 후 페이지나 내부망 자산을 검사하지 않습니다.
- `localhost`, 사설 IP, 내부망 스타일 호스트는 차단합니다.

즉, SiteGuard는 “공개적으로 보이는 보안 상태를 빠르게 점검하는 1차 스캐너”입니다.  
실제 서비스 보안 검증에는 인증된 테스트, 수동 리뷰, 권한 모델 검토가 반드시 추가로 필요합니다.

## 제품 관점에서의 특징

기존 보안 도구가 차갑고 기술적인 콘솔에 가까웠다면, SiteGuard는 다음 경험을 목표로 설계했습니다.

- 따뜻한 오렌지/베이지 톤의 SaaS 스타일 UI
- 결과를 한눈에 읽는 대시보드형 상단 영역
- 넓은 화면에서 잘 보이도록 구성한 분석 워크스페이스
- “문제가 있다”에서 끝나지 않고 “바로 어떻게 고칠지”까지 이어지는 UX

## 기술 스택

### Backend

- Node.js
- 내장 `http`, `https`, `dns`, `net` 기반 패시브 스캐너
- 메모리 기반 rate limit / concurrency guard / TTL cache

### Frontend

- Tailwind CSS
- 바닐라 JavaScript
- 단일 페이지 대시보드 UI

### Infra / Delivery

- Docker
- Render 배포 설정 포함

## 프로젝트 구조

```text
.
├─ public/
│  ├─ app.js
│  ├─ favicon.svg
│  ├─ index.html
│  ├─ robots.txt
│  └─ tailwind.css
├─ src/
│  ├─ remediation.js
│  ├─ runtime-guards.js
│  ├─ scanner.js
│  └─ tailwind.css
├─ test/
│  ├─ runtime-guards.test.js
│  └─ server.test.js
├─ Dockerfile
├─ render.yaml
├─ server.js
└─ package.json
```

## 로컬 실행

```bash
npm install
npm run build
npm run dev
```

브라우저에서 아래 주소를 열면 됩니다.

```text
http://localhost:3000
```

프로덕션 방식으로 바로 실행하려면:

```bash
npm start
```

## 테스트

```bash
npm test
```

현재 테스트는 다음을 검증합니다.

- rate limiter 동작
- TTL cache 동작
- concurrency guard 동작
- 프록시 환경에서의 클라이언트 IP / secure request 판별
- `/api/health`
- `/api/scan` 캐시 동작
- 정적 루트 페이지 응답

## 프론트엔드 빌드

UI는 Tailwind CSS 기반으로 구성되어 있으며, 빌드 결과는 `public/tailwind.css`로 생성됩니다.

```bash
npm run build
```

## 배포

이 프로젝트는 단일 Node 서버와 정적 자산으로 구성되어 있어 Render, Railway, Fly.io 같은 환경에 쉽게 배포할 수 있습니다.

### Render

레포에 포함된 `render.yaml`을 사용하면 바로 배포 구성을 가져갈 수 있습니다.

### Docker

레포에 포함된 `Dockerfile`로 이미지 빌드가 가능합니다.

```bash
docker build -t siteguard .
docker run -p 3000:3000 siteguard
```

## 환경 변수

| 이름 | 설명 | 기본값 |
|---|---|---|
| `PORT` | 서버 포트 | `3000` |
| `MAX_CONCURRENT_SCANS` | 동시에 처리할 스캔 수 | `4` |
| `RATE_LIMIT_MAX` | IP 기준 윈도우당 최대 요청 수 | `10` |
| `RATE_LIMIT_WINDOW_MS` | 레이트리밋 윈도우 | `60000` |
| `SCAN_CACHE_TTL_MS` | 결과 캐시 유지 시간 | `300000` |
| `SCAN_CACHE_MAX_ENTRIES` | 캐시 최대 엔트리 수 | `300` |

## 앞으로 확장할 수 있는 방향

- 도메인 소유 검증 후 더 깊은 `Verified Scan`
- 여러 URL을 한 화면에서 비교하는 비교 모드
- 프레임워크별 수정 가이드 강화
- CI에서 자동 보안 구성 점검 리포트 생성

## 주의

이 도구는 공개적으로 관찰 가능한 보안 상태를 빠르게 확인하는 데 최적화되어 있습니다.  
실제 운영 환경에서는 반드시 인증된 보안 테스트, 권한 검토, 로그 분석, 수동 점검을 함께 진행해야 합니다.
