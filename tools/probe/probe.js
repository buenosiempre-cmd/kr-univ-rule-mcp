#!/usr/bin/env node
/**
 * probe.js v2 — 서울 주요대학 규정집 시스템 탐지 + LawMaster 호환성 실증
 *
 * v1 대비 개선:
 *  1) 확장자(.srv/.do) 판정을 링크 추측이 아니라 **실제 엔드포인트 호출로 실증** (deep check)
 *  2) WAF/보안장비 차단 페이지 감지 → blocked로 정확 분류
 *  3) 판정 우선순위 도입 — 나쁜 판정이 좋은 판정을 덮지 못하게
 *  4) 최종 URL의 확장자도 지문 신호로 사용
 *
 * 실행: node probe.js [--only khu,ssu] [--json out.json] [--timeout 12000] [--no-deep]
 * ⚠️ 국내 IP 권장. 일부 대학은 해외/데이터센터 IP 차단.
 */
process.removeAllListeners('warning');
process.on('warning', w => { if (w.name !== 'DeprecationWarning') console.warn(w); });

const fetch = require('node-fetch');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36';

const ARGV = process.argv.slice(2);
const argOf = f => { const i = ARGV.indexOf(f); return i >= 0 ? ARGV[i + 1] : undefined; };
const ONLY = (argOf('--only') || '').split(',').map(s => s.trim()).filter(Boolean);
const OUT_JSON = argOf('--json');
const TIMEOUT = Number(argOf('--timeout') || 12000);
const NO_DEEP = ARGV.includes('--no-deep');
const DELAY_MS = 700;

const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'universities.json'), 'utf-8'));
let targets = cfg.universities;
if (ONLY.length) targets = targets.filter(u => ONLY.includes(u.key));

// ─── HTTP ───
let lastReq = 0;
async function request(url, opts = {}) {
  const wait = DELAY_MS - (Date.now() - lastReq);
  if (wait > 0) await new Promise(r => setTimeout(r, wait));
  lastReq = Date.now();
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers: {
      'User-Agent': UA,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'ko-KR,ko;q=0.9,en;q=0.5',
      ...(opts.body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
    },
    body: opts.body,
    timeout: TIMEOUT,
    redirect: 'follow',
  });
  const html = await res.text();
  return { status: res.status, url: res.url, html };
}

// ─── 헬퍼: 차단 감지 / 판정 우선순위 / 파서 ───
function looksBlocked(html, finalUrl) {
  if (/\/waf\/|deny\d*\.html/i.test(finalUrl)) return true;
  const head = html.slice(0, 4000);
  return /차단페이지|접근이 차단|비정상적인 접근|Access Denied|Web Application Firewall/i.test(head);
}

// 유효 응답(workingUrl)이 이미 잡힌 대학은 이후의 차단/503이 판정을 강등하지 못한다.
// (서울대 사례: HTTP로 200 응답을 받았는데 후속 HTTPS의 WAF 차단이 판정을 덮던 버그)
function canDemoteToBlocked(result) { return !result.workingUrl; }

const RANK = { 'lawmaster-srv': 6, 'lawmaster-do': 6, 'lawmaster-mixed': 6, 'lawmaster': 6,
               'custom': 4, 'blocked': 3, 'unknown': 2, 'not-rules': 1, 'dead': 0 };
function better(newV, curV) { return (RANK[newV] ?? 0) > (RANK[curV] ?? 0); }

// LawMaster 검색결과에서 (lawId, historyId, title) 추출 — dongguk 파서 + 신형 호환 일반화
function parseSearchHitsGeneric(html) {
  const $ = cheerio.load(html);
  const hits = []; const seen = new Set();
  const pushHit = (id, hid, title) => {
    const k = id + '_' + hid;
    if (!seen.has(k)) { seen.add(k); hits.push({ lawId: id, historyId: hid, title: title || '' }); }
  };
  $('tr').each(function () {
    const s = $(this).html() || '';
    const m = /lawSearchFullView\w*\(\s*'(\d+)'\s*,\s*'(\d+)'/.exec(s);
    if (!m) return;
    const st = []; let sm; const re = /showSearchText\(\s*(?:"|&quot;)([^"&]*)(?:"|&quot;)/g;
    while ((sm = re.exec(s)) !== null) st.push(sm[1]);
    pushHit(m[1], m[2], st[1] || st[0] || $(this).find('a').first().text().trim());
  });
  if (!hits.length) {  // 폴백: href의 SEQ 파라미터
    let m; const re = /SEQ=(\d+)&(?:amp;)?SEQ_HISTORY=(\d+)/g;
    while ((m = re.exec(html)) !== null && hits.length < 10) pushHit(m[1], m[2], '');
  }
  return hits;
}
function parseListPairs(html) {
  const pairs = []; const seen = new Set(); let m;
  const re1 = /fullPopupPost\((\d+),\s*(\d+)/g;
  while ((m = re1.exec(html)) !== null) { const k=m[1]+'_'+m[2]; if(!seen.has(k)){seen.add(k); pairs.push({lawId:m[1],historyId:m[2]});} }
  if (!pairs.length) {
    const re2 = /SEQ=(\d+)&(?:amp;)?SEQ_HISTORY=(\d+)/g;
    while ((m = re2.exec(html)) !== null && pairs.length < 10) { const k=m[1]+'_'+m[2]; if(!seen.has(k)){seen.add(k); pairs.push({lawId:m[1],historyId:m[2]});} }
  }
  return pairs;
}
function countArticles(html) {
  const $ = cheerio.load(html);
  const byClass = $('div.article').length;
  if (byClass) return { count: byClass, how: 'css' };
  const byText = ($('body').text().match(/제\d+조\(/g) || []).length;
  return { count: byText, how: 'regex' };
}

// ─── 지문 분석 ───
function fingerprint(html, finalUrl) {
  const $ = cheerio.load(html);
  const bodyText = $('body').text();
  const links = [];
  $('a[href], script[src], form[action]').each(function () {
    const v = $(this).attr('href') || $(this).attr('src') || $(this).attr('action') || '';
    if (v) links.push(v);
  });
  const allRefs = (links.join(' ') + ' ' + html).slice(0, 200000);

  const signals = {
    lmxsrv: /lmxsrv/i.test(allRefs) || /lmxsrv/i.test(finalUrl),
    srvExt: /\.srv(\?|["'\s]|$)/i.test(allRefs) || /\.srv(\?|#|$)/i.test(finalUrl),
    doExt: /lmxsrv\/[a-z]+\/[a-zA-Z]+\.do/i.test(allRefs) || (/lmxsrv/i.test(finalUrl) && /\.do(\?|#|$)/i.test(finalUrl)),
    lawFullContent: /lawFullContent/i.test(allRefs),
    lawSearchFullView: /lawSearchFullView/i.test(allRefs),
    showSearchText: /showSearchText/i.test(allRefs),
    histroySeq: /histroySeq/i.test(allRefs),
    fullbody: $('div.fullbody').length > 0,
    lawname: $('div.lawname').length > 0,
    tbodyClass: $('tbody.tbody').length > 0,
    infoLeft: $('p.infoLeft').length > 0,
    hasRuleWord: /규정|학칙|내규|세칙/.test(bodyText),
    title: ($('title').text() || '').trim().slice(0, 80),
  };

  const isLawSchool = /법학대학|법과대학|로스쿨|law school/i.test(signals.title + ' ' + bodyText.slice(0, 3000))
                      && !/규정관리|규정집|통합규정/i.test(signals.title);

  let verdict, confidence, note;
  const lmCore = [signals.lmxsrv, signals.lawFullContent, signals.showSearchText,
                  signals.histroySeq, signals.fullbody, signals.lawname,
                  signals.tbodyClass, signals.infoLeft].filter(Boolean).length;

  if (isLawSchool) {
    verdict = 'not-rules'; confidence = 'high';
    note = '법과대학 홈페이지 — 규정집 아님';
  } else if (signals.lmxsrv || lmCore >= 2) {
    if (signals.doExt && signals.srvExt) { verdict = 'lawmaster-mixed'; note = '.srv/.do 혼재 — 심층검증으로 판별'; }
    else if (signals.doExt) { verdict = 'lawmaster-do'; note = 'LawMaster(.do) — 심층검증 권장'; }
    else if (signals.srvExt) { verdict = 'lawmaster-srv'; note = 'LawMaster(.srv) — 심층검증 권장'; }
    else { verdict = 'lawmaster'; note = 'LawMaster 계열, 확장자 미확인 — 심층검증으로 판별'; }
    confidence = lmCore >= 4 ? 'high' : lmCore >= 2 ? 'medium' : 'low';
  } else if (/규정관리|규정집|통합규정|제규정/i.test(signals.title)) {
    verdict = 'custom'; confidence = 'medium';
    note = '규정집 확인(제목 기준). JS 렌더링 가능성 — 내부 API 확인 필요';
  } else if (signals.hasRuleWord) {
    verdict = 'custom'; confidence = 'medium';
    note = '자체 규정집 시스템. 전용 어댑터 필요';
  } else {
    verdict = 'unknown'; confidence = 'low';
    note = '규정집 페이지가 아니거나 JS 렌더링. 수동 확인 필요';
  }
  return { verdict, confidence, note, signals };
}

// ─── 심층검증: LawMaster 엔드포인트를 실제 호출해 dongguk 파서 호환성 실증 ───
async function deepCheck(originUrl, extHint) {
  const origin = new URL(originUrl).origin;
  const exts = extHint === 'do' ? ['do', 'srv'] : extHint === 'srv' ? ['srv', 'do'] : ['srv', 'do'];
  const compat = { verified: false, origin };

  for (const ext of exts) {
    const trial = { ext, listOk: false, searchOk: false, contentOk: false, hits: 0, articleCount: 0, sampleTitle: '' };
    let sample = null;

    // 1) 목록 GET
    try {
      const r = await request(`${origin}/lmxsrv/law/lawNewList.${ext}`);
      if (r.status === 200) {
        const pairs = parseListPairs(r.html);
        if (pairs.length) { trial.listOk = true; sample = pairs[0]; }
      }
    } catch (e) {}

    // 2) 검색 POST (dongguk 페이로드 그대로)
    try {
      const body = new URLSearchParams({ PAGE:'1', PAGE_SHOW:'5', LAWGROUP:'0', SEARCH_TYPE:'LAWNAME', SEARCH_TEXT:'학칙' }).toString();
      const r = await request(`${origin}/lmxsrv/search/lawSerach.${ext}`, { method: 'POST', body });
      if (r.status === 200) {
        const hits = parseSearchHitsGeneric(r.html);
        if (hits.length) {
          trial.searchOk = true; trial.hits = hits.length;
          trial.sampleTitle = hits[0].title;
          sample = sample || hits[0];
        }
      }
    } catch (e) {}

    // 3) 본문 GET (표본이 있을 때만)
    if (sample) {
      try {
        const r = await request(`${origin}/lmxsrv/law/lawFullContent.${ext}?SEQ=${sample.lawId}&SEQ_HISTORY=${sample.historyId}`);
        if (r.status === 200) {
          const $ = cheerio.load(r.html);
          const hasStruct = $('div.lawname').length > 0 || $('div.fullbody').length > 0;
          const art = countArticles(r.html);
          if (hasStruct || art.count > 0) { trial.contentOk = true; trial.articleCount = art.count; trial.articleHow = art.how; }
        }
      } catch (e) {}
    }

    if (trial.listOk || trial.searchOk) {
      Object.assign(compat, trial, { verified: true });
      return compat;
    }
  }
  compat.note = 'lmxsrv 지문은 있으나 표준 엔드포인트 불응답 — 신형/변형 가능, 수동 확인';
  return compat;
}

// ─── 대학별 탐지 ───
async function probeUniversity(u) {
  const result = {
    key: u.key, name: u.name, declared: u.known || null, status: u.status,
    workingUrl: null, httpStatus: null,
    verdict: 'dead', confidence: 'n/a', note: '', signals: null, compat: null,
    attempts: [],
  };

  for (const base of u.urls) {
    const paths = (base.includes('?') || /\.(do|jsp|html)$/i.test(base)) ? [''] : ['/lmxsrv/main/main.srv', '/lmxsrv/main/main.do', '/'];
    for (const p of paths) {
      const url = base + p;
      try {
        const r = await request(url);
        result.attempts.push({ url, status: r.status, bytes: r.html.length });

        if (r.status === 503) {
          if (canDemoteToBlocked(result) && better('blocked', result.verdict)) { result.verdict = 'blocked'; result.note = '503 — IP 차단. 국내망에서 재시도'; }
          continue;
        }
        if (looksBlocked(r.html, r.url)) {
          if (canDemoteToBlocked(result) && better('blocked', result.verdict)) { result.verdict = 'blocked'; result.note = 'WAF/보안장비 차단 — 국내망에서 재시도'; }
          continue;
        }
        if (r.status >= 400 || r.html.length < 200) continue;

        const fp = fingerprint(r.html, r.url);
        if (fp.verdict.startsWith('lawmaster') || better(fp.verdict, result.verdict)) {
          result.workingUrl = r.url; result.httpStatus = r.status;
          Object.assign(result, { verdict: fp.verdict, confidence: fp.confidence, note: fp.note, signals: fp.signals });
        }
        if (fp.verdict.startsWith('lawmaster')) return result;
      } catch (e) {
        result.attempts.push({ url, error: e.code || e.message.slice(0, 60) });
      }
    }
  }
  if (!result.workingUrl && result.verdict === 'dead') {
    result.note = '접근 가능한 URL 없음 — 도메인 추정이 틀렸거나 로그인 필요';
  }
  return result;
}

// ─── 실행 ───
const ICON = { 'lawmaster-srv':'🟢','lawmaster-do':'🟡','lawmaster-mixed':'🟡','lawmaster':'🟠',
               'custom':'🔵','unknown':'⚪','not-rules':'🟤','blocked':'🔴','dead':'⚫' };

async function main() {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔍 서울 주요대학 규정집 탐지 v2 (심층검증 ' + (NO_DEEP ? 'OFF' : 'ON') + ')');
  console.log(`   대상 ${targets.length}개 · 타임아웃 ${TIMEOUT}ms`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const results = [];
  for (const u of targets) {
    process.stdout.write(`\n[${u.key}] ${u.name} ... `);
    const r = await probeUniversity(u);

    // 심층검증: LawMaster 계열이면 실제 엔드포인트 호출로 실증
    if (!NO_DEEP && r.verdict.startsWith('lawmaster') && r.workingUrl) {
      const hint = r.verdict === 'lawmaster-do' ? 'do' : r.verdict === 'lawmaster-srv' ? 'srv' : null;
      r.compat = await deepCheck(r.workingUrl, hint);
      if (r.compat.verified) {
        r.verdict = `lawmaster-${r.compat.ext}`;
        r.confidence = 'verified';
        r.note = `실증 완료 — dongguk 파서 호환 (검색 ${r.compat.searchOk ? '✅' : '—'}${r.compat.hits ? ` ${r.compat.hits}건` : ''}, 본문 ${r.compat.contentOk ? `✅ 조문 ${r.compat.articleCount}` : '—'})`;
      } else {
        r.confidence = 'low';
        r.note = r.compat.note;
      }
    }

    results.push(r);
    console.log(`${ICON[r.verdict] || '⚪'} ${r.verdict} (${r.confidence})`);
    if (r.workingUrl) console.log(`      URL: ${r.workingUrl}`);
    console.log(`      ${r.note}`);
    if (r.compat?.verified) {
      console.log(`      🔬 ext=.${r.compat.ext} | 목록 ${r.compat.listOk?'✅':'❌'} | 검색 ${r.compat.searchOk?'✅':'❌'} | 본문 ${r.compat.contentOk?'✅':'❌'}${r.compat.sampleTitle ? ` | 예: ${r.compat.sampleTitle.slice(0,20)}` : ''}`);
    }
  }

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📊 요약');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const by = {};
  results.forEach(r => { (by[r.verdict] ||= []).push(r); });
  for (const v of ['lawmaster-srv','lawmaster-do','lawmaster-mixed','lawmaster','custom','unknown','not-rules','blocked','dead']) {
    if (!by[v]) continue;
    console.log(`\n${ICON[v]} ${v} — ${by[v].length}개`);
    by[v].forEach(r => console.log(`   · ${r.name}${r.confidence==='verified' ? ' [실증]' : ''}${r.workingUrl ? ' — ' + r.workingUrl : ''}`));
  }
  const verified = results.filter(r => r.confidence === 'verified').length;
  const lm = results.filter(r => r.verdict.startsWith('lawmaster')).length;
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`✅ LawMaster 계열: ${lm}개 (그중 파서 호환 실증: ${verified}개)`);
  console.log(`🔵 전용 어댑터 필요: ${by['custom']?.length || 0}개`);
  console.log(`🔴 국내망 재시도 필요: ${by['blocked']?.length || 0}개`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  if (OUT_JSON) {
    fs.writeFileSync(OUT_JSON, JSON.stringify({ probedAt: new Date().toISOString(), version: 2, results }, null, 2), 'utf-8');
    console.log(`\n💾 저장: ${OUT_JSON}`);
  }
}

main().catch(e => { console.error('\n💥', e.message); process.exit(1); });
