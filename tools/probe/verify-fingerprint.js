// probe.js v2 헬퍼·지문 로직 단위 검증 (네트워크 불필요)
const cheerio = require('cheerio');
const src = require('fs').readFileSync('./probe.js', 'utf-8');
const slice = src.slice(src.indexOf('// ─── 헬퍼'), src.indexOf('// ─── 심층검증'));
eval(slice);

let pass=0, fail=0;
const check=(n,c,d='')=>{ c?(console.log(`  ✅ ${n}`),pass++):(console.log(`  ❌ ${n} ${d}`),fail++); };

console.log('\n[A] 지문 — 기본 판정');
const lmFull = `<html><head><title>통합규정관리시스템</title></head><body>
<p class="infoLeft">검색 <span>3</span>건</p>
<tbody class="tbody"><tr><td class="tbody_txt"><a href="javascript:lawSearchFullViewSrv('491','1437');">
<span onclick="showSearchText(&quot;재정시행세칙&quot;)">x</span></a></td></tr></tbody>
<div class="fullbody"><div class="lawname">재정시행세칙</div></div>
<a href="/lmxsrv/law/lawFullContent.srv?SEQ=1">전문</a>
<select id="histroySeq"><option value="1437">v</option></select></body></html>`;
let r = fingerprint(lmFull, 'https://rule.dongguk.edu/lmxsrv/main/main.srv');
check('완전 지문 → lawmaster-srv/high', r.verdict==='lawmaster-srv' && r.confidence==='high', `(${r.verdict}/${r.confidence})`);

r = fingerprint(`<html><body><div class="fullbody"><div class="lawname">x</div></div>
<a href="/lmxsrv/law/lawFullContent.do?SEQ=1">y</a></body></html>`, 'https://rule.khu.ac.kr/');
check('.do 링크만 → lawmaster-do', r.verdict==='lawmaster-do', `(${r.verdict})`);

console.log('\n[B] 지문 — v1 버그 회귀 케이스');
// HUFS 회귀: 링크에 확장자 없음, 최종 URL이 .do
r = fingerprint(`<html><body><p>규정</p><script src="/lmxsrv/js/m.js"></script></body></html>`,
                'https://law.hufs.ac.kr/lmxsrv/main/main.do');
check('링크無+최종URL .do → lawmaster-do (HUFS 회귀)', r.verdict==='lawmaster-do', `(${r.verdict})`);
// SSU 회귀: 최종 URL .srv + 내부링크 .do → mixed로 정직하게
r = fingerprint(`<html><body><a href="/lmxsrv/law/lawList.do">목록</a></body></html>`,
                'http://rule.ssu.ac.kr/lmxsrv/main/main.srv');
check('최종URL .srv + 링크 .do → lawmaster-mixed (SSU 회귀)', r.verdict==='lawmaster-mixed', `(${r.verdict})`);
// 확장자 신호 전무 → generic lawmaster
r = fingerprint(`<html><body><iframe src="/lmxsrv/main/frame"></iframe></body></html>`, 'https://x.ac.kr/');
check('lmxsrv만, 확장자 미상 → lawmaster(generic)', r.verdict==='lawmaster', `(${r.verdict})`);

console.log('\n[C] 지문 — 오탐/특수');
r = fingerprint(`<html><head><title>중앙대학교 법학대학</title></head><body><p>법학대학 소개, 규정 안내</p></body></html>`, 'https://laws.cau.ac.kr/');
check('법과대학 → not-rules', r.verdict==='not-rules', `(${r.verdict})`);
r = fingerprint(`<html><head><title>단국대학교 규정관리시스템</title></head><body><div id="app"></div></body></html>`, 'https://rule.dankook.ac.kr/');
check('JS렌더링 규정집(제목) → custom', r.verdict==='custom', `(${r.verdict})`);
r = fingerprint(`<html><head><title>Welcome</title></head><body><h1>홈</h1></body></html>`, 'https://x.ac.kr/');
check('무관 페이지 → unknown', r.verdict==='unknown', `(${r.verdict})`);

console.log('\n[D] 차단 감지');
check('WAF deny URL', looksBlocked('<html></html>', 'https://snucert.snu.ac.kr/waf/deny02.html')===true);
check('차단페이지 타이틀', looksBlocked('<html><head><title>차단페이지</title></head></html>', 'https://x/')===true);
check('정상 페이지 → false', looksBlocked('<html><title>규정집</title></html>', 'https://rule.x.ac.kr/')===false);

console.log('\n[E] 판정 우선순위');
check('custom > not-rules', better('custom','not-rules')===true);
check('lawmaster-do > custom', better('lawmaster-do','custom')===true);
check('blocked > unknown', better('blocked','unknown')===true);
check('unknown이 custom 못 덮음', better('unknown','custom')===false);

console.log('\n[F] 파서 (신형 호환 일반화)');
const srvHtml = `<table><tbody class="tbody"><tr><td class="tbody_txt"><a href="javascript:lawSearchFullViewSrv('491','1437');">
<span onclick='showSearchText("3-2-1")'>c</span><span onclick='showSearchText("재정시행세칙")'>t</span></a></td></tr></tbody></table>`;
let hits = parseSearchHitsGeneric(srvHtml);
check('구형(Srv접미) 파싱', hits.length===1 && hits[0].lawId==='491' && hits[0].title==='재정시행세칙', JSON.stringify(hits[0]||{}));
const doHtml = `<table><tr><td><a href="javascript:lawSearchFullView('75','324');">회계규정</a></td></tr></table>`;
hits = parseSearchHitsGeneric(doHtml);
check('신형(접미無) 파싱', hits.length===1 && hits[0].lawId==='75', JSON.stringify(hits[0]||{}));
hits = parseSearchHitsGeneric(`<a href="/x?SEQ=31&amp;SEQ_HISTORY=1686">규정</a>`);
check('SEQ href 폴백', hits.length===1 && hits[0].historyId==='1686');
const pairs = parseListPairs(`fullPopupPost(73, 3551,'3551'); fullPopupPost(73, 3551,'x'); fullPopupPost(80, 900,'y');`);
check('목록 pairs + 중복제거', pairs.length===2 && pairs[0].lawId==='73', `(${pairs.length}건)`);

console.log('\n[G] 조문 카운트');
let a = countArticles(`<div class="fullbody"><div class="article">제1조(목적)</div><div class="article">제2조(범위)</div></div>`);
check('CSS 기반', a.count===2 && a.how==='css', JSON.stringify(a));
a = countArticles(`<body>제1조(목적) 내용 제2조(정의) 내용 제3조(적용)</body>`);
check('정규식 폴백', a.count===3 && a.how==='regex', JSON.stringify(a));

console.log(`\n📊 v2 단위 검증: ${pass}개 통과 / ${fail}개 실패`);
process.exit(fail>0?1:0);
