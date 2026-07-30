# kr-univ-rule-probe v2

서울 주요대학 규정집 시스템 자동 탐지 도구.
[dongguk-rule-mcp](https://github.com/buenosiempre-cmd/dongguk-rule-mcp)의 LawMaster 파서를
어느 대학에 그대로 재사용할 수 있는지 데이터로 가려냅니다.

## 실행

```bash
npm install
node probe.js --json result.json      # 전체 18개 탐지 + 심층검증
node probe.js --no-deep               # 지문 탐지만 (심층검증 생략)
node probe.js --only khu,ssu          # 특정 대학만
node probe.js --timeout 15000         # 타임아웃 조정
```

⚠️ **국내 IP에서 실행하세요.** 동국대·성균관대 등은 해외/데이터센터 IP를 차단합니다.

## 판정 결과

| 판정 | 의미 | 대응 |
|---|---|---|
| 🟢 `lawmaster-srv` | 동국대와 동일 계열 | base URL 교체만으로 지원 |
| 🟡 `lawmaster-do` | LawMaster 변형(.do) | config에 확장자 지정 |
| 🔵 `custom` | 자체 시스템 | 전용 어댑터 개발 |
| 🟤 `not-rules` | 법과대학 등 오탐 | 다른 도메인 탐색 |
| 🔴 `blocked` | IP 차단(503) | 국내망에서 재시도 |
| ⚫ `dead` | 접근 불가 | 도메인 재조사 |

## v2 심층검증 (핵심)

지문만 믿지 않습니다. LawMaster로 감지되면 **실제 엔드포인트를 호출해 실증**합니다:
1. `GET /lmxsrv/law/lawNewList.{ext}` — 목록 파싱 (fullPopupPost/SEQ 추출)
2. `POST /lmxsrv/search/lawSerach.{ext}` — dongguk 검색 페이로드 그대로
3. `GET /lmxsrv/law/lawFullContent.{ext}` — 본문 구조(div.lawname/article) + 조문 수 파싱

`[실증]` 마크 = dongguk-rule-mcp 파서가 그 대학에서 실제로 동작함을 확인한 것.
.srv/.do 확장자도 추측이 아니라 응답으로 판별합니다.

## 탐지 원리

LawMaster 고유 지문을 HTML에서 찾습니다: `lmxsrv` 경로, `lawFullContent`,
`showSearchText`, `div.fullbody`, `div.lawname`, `tbody.tbody`, `p.infoLeft`,
그리고 `histroySeq`(솔루션 특유의 오타 id). 2개 이상 일치하면 LawMaster 계열로 판정합니다.

## 검증

```bash
node verify-fingerprint.js   # 지문·판정 로직 23개 단위 테스트 (네트워크 불필요)
```
