const REMEDIATION_MAP = {
  no_https: {
    title: "HTTPS를 기본 진입점으로 강제하세요",
    whyItMatters: "평문 HTTP는 중간자 공격과 세션 탈취에 취약합니다.",
    actions: [
      "유효한 TLS 인증서를 적용하세요.",
      "모든 HTTP 요청을 301 또는 308으로 HTTPS로 리다이렉트하세요.",
      "외부 링크와 canonical URL도 HTTPS로 통일하세요."
    ],
    snippets: [
      {
        label: "Nginx redirect",
        code: "server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}"
      }
    ],
    references: [
      {
        label: "OWASP Secure Headers Project",
        href: "https://owasp.org/www-project-secure-headers/"
      }
    ]
  },
  no_https_redirect: {
    title: "HTTP 요청을 HTTPS로 리다이렉트하세요",
    whyItMatters: "HTTPS가 있더라도 HTTP 진입점이 남아 있으면 사용자가 평문 연결로 머무를 수 있습니다.",
    actions: [
      "모든 HTTP 요청에 301 또는 308 redirect를 적용하세요.",
      "리다이렉트 체인이 길어지지 않도록 한 번에 최종 HTTPS로 보내세요."
    ],
    snippets: [
      {
        label: "Express redirect",
        code: "app.enable('trust proxy');\napp.use((req, res, next) => {\n  if (req.secure) return next();\n  return res.redirect(308, `https://${req.headers.host}${req.originalUrl}`);\n});"
      }
    ],
    references: [
      {
        label: "OWASP Secure Headers Project",
        href: "https://owasp.org/www-project-secure-headers/"
      }
    ]
  },
  invalid_tls_cert: {
    title: "TLS 인증서 오류를 해결하세요",
    whyItMatters: "브라우저 경고는 사용자 신뢰를 잃게 하고, 실제 보안 위험을 의미할 수 있습니다.",
    actions: [
      "도메인 일치 여부와 만료일을 확인하세요.",
      "전체 인증서 체인을 정확히 배포하세요.",
      "자동 갱신을 설정하세요."
    ],
    snippets: [],
    references: [
      {
        label: "OWASP Secure Headers Project",
        href: "https://owasp.org/www-project-secure-headers/"
      }
    ]
  },
  expiring_tls_cert: {
    title: "TLS 인증서 만료를 선제적으로 갱신하세요",
    whyItMatters: "인증서 만료는 서비스 신뢰와 접근성을 동시에 깨뜨립니다.",
    actions: [
      "만료 전에 자동 갱신을 설정하세요.",
      "모니터링 또는 알림을 붙이세요."
    ],
    snippets: [],
    references: [
      {
        label: "OWASP Secure Headers Project",
        href: "https://owasp.org/www-project-secure-headers/"
      }
    ]
  },
  missing_hsts: {
    title: "HSTS를 추가하세요",
    whyItMatters: "브라우저가 HTTPS 강제를 기억하지 못하면 downgrade 공격 여지가 남습니다.",
    actions: [
      "충분한 max-age와 함께 Strict-Transport-Security를 추가하세요.",
      "서브도메인까지 정책을 확대할 준비가 되면 includeSubDomains를 사용하세요."
    ],
    snippets: [
      {
        label: "Nginx HSTS",
        code: "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
      },
      {
        label: "Next.js headers",
        code: "async headers() {\n  return [\n    {\n      source: '/(.*)',\n      headers: [\n        { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }\n      ]\n    }\n  ];\n}"
      }
    ],
    references: [
      {
        label: "MDN Strict-Transport-Security",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"
      },
      {
        label: "OWASP Secure Headers Project",
        href: "https://owasp.org/www-project-secure-headers/"
      }
    ]
  },
  weak_hsts: {
    title: "HSTS 강도를 높이세요",
    whyItMatters: "너무 짧은 max-age는 HTTPS 강제의 효과를 크게 줄입니다.",
    actions: [
      "max-age를 최소 15552000 이상으로 올리세요.",
      "운영 범위를 검토한 뒤 includeSubDomains와 preload를 고려하세요."
    ],
    snippets: [],
    references: [
      {
        label: "MDN Strict-Transport-Security",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"
      }
    ]
  },
  missing_csp: {
    title: "Content-Security-Policy를 추가하세요",
    whyItMatters: "CSP는 XSS와 악성 리소스 로딩의 피해 범위를 크게 줄여주는 핵심 방어선입니다.",
    actions: [
      "우선 보수적인 default-src를 적용하세요.",
      "script-src, style-src, img-src, connect-src를 서비스에 맞게 명시하세요.",
      "가능하면 nonce 또는 hash 기반 정책으로 강화하세요."
    ],
    snippets: [
      {
        label: "Starter CSP",
        code: "Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests;"
      }
    ],
    references: [
      {
        label: "MDN Content-Security-Policy",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy"
      }
    ]
  },
  weak_csp: {
    title: "CSP를 더 엄격하게 조정하세요",
    whyItMatters: "'unsafe-inline' 또는 와일드카드 사용은 CSP의 보호 효과를 크게 약화시킵니다.",
    actions: [
      "script-src와 default-src의 와일드카드를 제거하세요.",
      "가능하면 unsafe-inline, unsafe-eval을 제거하세요.",
      "정말 필요한 출처만 allowlist에 남기세요."
    ],
    snippets: [],
    references: [
      {
        label: "MDN Content-Security-Policy",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy"
      }
    ]
  },
  missing_frame_protection: {
    title: "클릭재킹 방어를 추가하세요",
    whyItMatters: "다른 사이트가 페이지를 iframe에 넣으면 클릭재킹에 노출될 수 있습니다.",
    actions: [
      "X-Frame-Options: DENY 또는 SAMEORIGIN을 적용하세요.",
      "가능하면 CSP frame-ancestors로 더 정밀하게 제어하세요."
    ],
    snippets: [
      {
        label: "Frame protection headers",
        code: "X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors 'none';"
      }
    ],
    references: [
      {
        label: "MDN X-Frame-Options",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
      }
    ]
  },
  missing_nosniff: {
    title: "nosniff를 설정하세요",
    whyItMatters: "브라우저의 MIME sniffing을 막아 의도치 않은 스크립트 실행 위험을 줄입니다.",
    actions: [
      "X-Content-Type-Options: nosniff를 추가하세요."
    ],
    snippets: [
      {
        label: "Simple header",
        code: "X-Content-Type-Options: nosniff"
      }
    ],
    references: [
      {
        label: "MDN X-Content-Type-Options",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options"
      }
    ]
  },
  missing_referrer_policy: {
    title: "Referrer-Policy를 명시하세요",
    whyItMatters: "내부 경로와 쿼리 정보가 외부로 과하게 노출될 수 있습니다.",
    actions: [
      "strict-origin-when-cross-origin 또는 no-referrer를 기본값으로 검토하세요."
    ],
    snippets: [
      {
        label: "Recommended policy",
        code: "Referrer-Policy: strict-origin-when-cross-origin"
      }
    ],
    references: [
      {
        label: "MDN Referrer-Policy",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy"
      }
    ]
  },
  weak_referrer_policy: {
    title: "Referrer-Policy를 더 보수적으로 바꾸세요",
    whyItMatters: "unsafe-url, origin 계열은 불필요한 참조 정보 노출을 유발할 수 있습니다.",
    actions: [
      "strict-origin-when-cross-origin 또는 no-referrer로 조정하세요."
    ],
    snippets: [],
    references: [
      {
        label: "MDN Referrer-Policy",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy"
      }
    ]
  },
  missing_permissions_policy: {
    title: "Permissions-Policy를 추가하세요",
    whyItMatters: "카메라, 마이크, 위치 같은 민감한 브라우저 기능 접근을 더 엄격하게 제한할 수 있습니다.",
    actions: [
      "필요하지 않은 기능은 명시적으로 비활성화하세요.",
      "서비스에 필요한 최소 권한만 남기세요."
    ],
    snippets: [
      {
        label: "Restrictive example",
        code: "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
      }
    ],
    references: [
      {
        label: "MDN Permissions Policy",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Permissions_Policy"
      }
    ]
  },
  insecure_cookie: {
    title: "쿠키 속성을 강화하세요",
    whyItMatters: "세션 쿠키가 Secure, HttpOnly, SameSite 없이 배포되면 탈취와 CSRF 위험이 커집니다.",
    actions: [
      "민감한 쿠키에는 Secure와 HttpOnly를 적용하세요.",
      "SameSite=Lax 또는 Strict를 기본으로 검토하세요.",
      "세션 식별자는 HTTPS에서만 전송되게 하세요."
    ],
    snippets: [
      {
        label: "Express cookie",
        code: "res.cookie('session', token, {\n  secure: true,\n  httpOnly: true,\n  sameSite: 'lax'\n});"
      }
    ],
    references: [
      {
        label: "MDN Secure Cookie Configuration",
        href: "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies"
      }
    ]
  },
  permissive_cors: {
    title: "CORS 정책을 좁히세요",
    whyItMatters: "과도하게 열린 CORS는 의도치 않은 cross-origin 데이터 접근을 허용할 수 있습니다.",
    actions: [
      "Access-Control-Allow-Origin에 필요한 출처만 허용하세요.",
      "credentials가 필요한 경우 와일드카드를 함께 사용하지 마세요."
    ],
    snippets: [
      {
        label: "Express CORS",
        code: "app.use((req, res, next) => {\n  res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');\n  res.setHeader('Vary', 'Origin');\n  next();\n});"
      }
    ],
    references: []
  },
  stack_header_exposed: {
    title: "기술 스택 노출을 줄이세요",
    whyItMatters: "버전과 프레임워크 정보는 공격자에게 탐색 힌트를 제공합니다.",
    actions: [
      "Server, X-Powered-By 같은 헤더를 제거하거나 일반화하세요.",
      "프레임워크 기본 노출 설정을 비활성화하세요."
    ],
    snippets: [
      {
        label: "Express",
        code: "app.disable('x-powered-by');"
      }
    ],
    references: []
  },
  mixed_content: {
    title: "HTTPS 페이지의 혼합 콘텐츠를 제거하세요",
    whyItMatters: "HTTPS 문서 안의 HTTP 리소스는 보안 경고와 콘텐츠 변조 위험을 만듭니다.",
    actions: [
      "http:// 리소스를 https:// 또는 상대 경로로 교체하세요.",
      "가능하면 CSP upgrade-insecure-requests를 함께 사용하세요."
    ],
    snippets: [],
    references: [
      {
        label: "MDN Content-Security-Policy",
        href: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy"
      }
    ]
  },
  insecure_login_form: {
    title: "로그인 폼 전송 방식을 안전하게 바꾸세요",
    whyItMatters: "비밀번호가 GET 또는 평문 HTTP로 전송되면 URL, 로그, 프록시에 남을 수 있습니다.",
    actions: [
      "비밀번호 폼은 반드시 POST와 HTTPS를 사용하세요.",
      "외부 action URL을 사용한다면 전송 목적지를 다시 검토하세요."
    ],
    snippets: [
      {
        label: "Safe form",
        code: "<form method=\"post\" action=\"/login\">\n  <input type=\"password\" name=\"password\" />\n</form>"
      }
    ],
    references: []
  },
  missing_security_txt: {
    title: "security.txt를 공개하세요",
    whyItMatters: "외부 제보자가 올바른 연락처로 바로 전달할 수 있어 대응 속도와 신뢰도가 좋아집니다.",
    actions: [
      "/.well-known/security.txt 또는 /security.txt에 Contact와 Expires를 포함한 파일을 배포하세요.",
      "가능하면 Preferred-Languages, Canonical, PGP 정보도 함께 적어 주세요."
    ],
    snippets: [
      {
        label: "security.txt 예시",
        code: "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:00Z\nPreferred-Languages: ko, en\nCanonical: https://example.com/.well-known/security.txt"
      }
    ],
    references: [
      {
        label: "RFC 9116",
        href: "https://www.rfc-editor.org/rfc/rfc9116.html"
      }
    ]
  },
  incomplete_security_txt: {
    title: "security.txt 정보를 보완하세요",
    whyItMatters: "연락처나 만료일이 빠져 있으면 제보자가 실제로 사용 가능한 경로인지 판단하기 어렵습니다.",
    actions: [
      "Contact와 Expires를 모두 포함해 파일이 유효한 기간과 연락 수단을 분명히 하세요.",
      "운영 흐름에 맞으면 Canonical과 Preferred-Languages도 추가하세요."
    ],
    snippets: [],
    references: [
      {
        label: "RFC 9116",
        href: "https://www.rfc-editor.org/rfc/rfc9116.html"
      }
    ]
  },
  stale_security_txt: {
    title: "security.txt 만료일을 갱신하세요",
    whyItMatters: "만료된 security.txt는 실제로 관리 중인지 확신을 주지 못해 외부 제보가 지연될 수 있습니다.",
    actions: [
      "Expires 값을 앞으로 유효한 날짜로 갱신하세요.",
      "기재된 연락처가 지금도 실제로 운영 중인지 함께 확인하세요."
    ],
    snippets: [],
    references: [
      {
        label: "RFC 9116",
        href: "https://www.rfc-editor.org/rfc/rfc9116.html"
      }
    ]
  }
};

export function attachRemediation(findings) {
  return findings.map((finding) => ({
    ...finding,
    remediation: REMEDIATION_MAP[finding.id] || null
  }));
}
