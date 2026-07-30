# kr-univ-rule-mcp

한국 주요대학 규정집을 AI(MCP)에서 검색·조회하기 위한 멀티 대학 프로젝트.

> [korean-law-mcp](https://github.com/chrisryugj/korean-law-mcp)가 공무원에게 법령을 열어줬듯,
> 이 프로젝트는 대학 교직원에게 규정을 열어주는 것을 목표로 합니다.
> 출발점: [dongguk-rule-mcp](https://github.com/buenosiempre-cmd/dongguk-rule-mcp) (동국대, 검증 109개 통과)

## 왜 가능한가

다수 대학이 동일한 상용 솔루션(LawMaster, `lmxsrv`)을 씁니다.
**파서 하나로 여러 대학을 동시에 지원**할 수 있다는 뜻입니다.
`tools/probe`가 18개 대학을 실측해 이를 데이터로 확인했습니다.

## 실측 지형도 (2026-07, tools/probe v2)

| 분류 | 대학 | 상태 |
|---|---|---|
| 🟢 LawMaster **실증** | 고려, 서울시립, 건국, 국민, 숭실 (+동국) | dongguk 파서로 목록·본문 파싱 확인 |
| 🟡 LawMaster 미실증 | 경희, 한국외대 | 지문 확인, 엔드포인트 변형 확인 필요 |
| 🔵 자체 시스템 | 연세, 서강, 성균관, 한양, 세종, 이화 | 전용 어댑터 필요 |
| 🔴 국내망 필요 | 동국, 서울대, 중앙, 단국 | 데이터센터 IP 차단 — 국내에서 재탐지 |
| ⚫ URL 미확인 | 홍익 | 규정집 도메인 재조사 |

핵심 발견: `.do` 신형은 검색 엔드포인트만 다르고 목록·본문 구조는 동일 →
목록 기반 필터로 검색을 대체 가능.

## 구조

```
tools/probe/     탐지·실증 도구 (완료) — 대학별 시스템 분류 + LawMaster 호환 실증
src/             [예정] MCP 서버 본체 — 멀티 어댑터
  adapters/
    lawmaster.js [예정] 1개 파서로 LawMaster 8개교 지원
    yonsei.js …  [예정] 자체 시스템 어댑터
config/          [예정] 대학별 base URL·확장자 설정
```

## 로드맵

1. **Phase 1** — LawMaster 어댑터: 실증된 6개교 + 국내망 재탐지분 동시 지원
2. **Phase 2** — 자체 시스템 어댑터 (연세·성균관 우선)
3. **Phase 3** — 오픈소스 기여 모델: 각 대학 교직원이 자기 학교 어댑터 유지

## 탐지 도구 실행

```bash
cd tools/probe && npm install
node probe.js --json result.json     # ⚠️ 국내 IP 권장
npm test                              # 단위 검증 21개 (네트워크 불필요)
```

## 기여

자기 대학 어댑터를 추가하고 싶은 교직원·개발자 환영합니다.
`tools/probe`로 소속 대학을 탐지한 결과(JSON)와 함께 이슈를 열어주세요.

## 크레딧

- 기획·개발: 오승훈 (동국대학교 재무팀)
- LawMaster 파싱 원형: 서준호 (dongguk-rule-mcp Python 원본)
- 영감: 류승인 (광진구청, korean-law-mcp)

## 라이선스

MIT
