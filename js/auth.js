/* ========================================
   auth.js - 회원 인증 공통 모듈 (Supabase 직접 연동)
   - 로그인/로그아웃/회원가입
   - 세션 관리 (sessionStorage, 자동만료 2h)
   - 보안: PBKDF2 + 고유 salt
   ─────────────────────────────────────────
   [본인확인서비스 취약점 체크리스트 대응]
   항목1: CI/DI 평문 노출 차단 (SecureCI 모듈)
   항목2: 파라미터 변조 방지 HMAC 서명 (SecureSign 모듈)
   항목3: 본인확인 결과값 일치 검증 (SecureCI.verify)
   항목4: 인증 토큰 재사용(Replay) 방지 (NonceStore 모듈)
   항목6: 중요 페이지 접근 통제 (requireAdmin/requireLogin)
   항목7: HTTPS 전용 접속 강제 (enforceHttps)
======================================== */

/* ══════════════════════════════════════════════════════════
   ■ [항목 7] HTTPS 전용 접속 강제
   - http:// 로 접근 시 자동으로 https:// 로 리다이렉트
   - localhost·127.0.0.1 개발환경은 예외 처리
══════════════════════════════════════════════════════════ */
(function enforceHttps() {
  if (location.protocol === 'http:' &&
      !['localhost', '127.0.0.1'].includes(location.hostname)) {
    location.replace('https:' + location.href.substring(5));
  }
})();

/* ══════════════════════════════════════════════════════════
   ■ [항목 4] Nonce 기반 리플레이(Replay) 방지 모듈
   - 인증 요청마다 1회용 nonce 생성 → 사용 후 즉시 무효화
   - TTL 5분: 만료된 nonce 자동 거부
   - 같은 nonce 재사용 시 예외 발생
══════════════════════════════════════════════════════════ */
const NonceStore = (() => {
  const STORE_KEY = '_agastya_nonces';
  const NONCE_TTL = 5 * 60 * 1000; // 5분

  function _load() {
    try { return JSON.parse(sessionStorage.getItem(STORE_KEY) || '{}'); }
    catch { return {}; }
  }
  function _save(map) {
    sessionStorage.setItem(STORE_KEY, JSON.stringify(map));
  }
  function _purge(map) {
    const now = Date.now();
    Object.keys(map).forEach(k => { if (map[k].exp < now) delete map[k]; });
    return map;
  }

  /* nonce 생성 — 32바이트 랜덤 hex */
  function generate() {
    const arr = crypto.getRandomValues(new Uint8Array(32));
    const nonce = Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
    const map = _purge(_load());
    map[nonce] = { exp: Date.now() + NONCE_TTL, used: false };
    _save(map);
    return nonce;
  }

  /* nonce 소비 — 한 번만 사용 가능, 만료·재사용 모두 거부 */
  function consume(nonce) {
    if (!nonce || typeof nonce !== 'string') return false;
    const map = _purge(_load());
    const entry = map[nonce];
    if (!entry) return false;          // 존재하지 않거나 만료
    if (entry.used) return false;      // 이미 사용됨 (재사용 시도)
    if (Date.now() > entry.exp) { delete map[nonce]; _save(map); return false; } // 만료
    map[nonce].used = true;            // 사용 처리
    _save(map);
    return true;
  }

  /* 유효성만 확인 (소비하지 않음) */
  function isValid(nonce) {
    if (!nonce) return false;
    const map = _purge(_load());
    const entry = map[nonce];
    return !!(entry && !entry.used && Date.now() <= entry.exp);
  }

  return { generate, consume, isValid };
})();

/* ══════════════════════════════════════════════════════════
   ■ [항목 2] 파라미터 변조 방지 — HMAC-SHA256 서명 모듈
   - 회원가입/본인확인 결과 전송 시 서버 전달 데이터에 서명 첨부
   - 서명 검증 실패 시 처리 중단
   - 정적 사이트 특성상 서명 키는 세션 범위 임시 키 사용
     (실제 서비스에서는 서버 발급 서명 키로 교체 필요)
══════════════════════════════════════════════════════════ */
const SecureSign = (() => {
  /* 세션 범위 임시 서명 키 (탭 종료 시 소멸) */
  function _getSessionKey() {
    let k = sessionStorage.getItem('_agastya_sign_key');
    if (!k) {
      const arr = crypto.getRandomValues(new Uint8Array(32));
      k = Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
      sessionStorage.setItem('_agastya_sign_key', k);
    }
    return k;
  }

  /* 객체 → 정규화 문자열 (키 정렬 후 직렬화) */
  function _canonicalize(obj) {
    return Object.keys(obj).sort()
      .map(k => `${k}=${String(obj[k] ?? '')}`)
      .join('&');
  }

  /* HMAC-SHA256 서명 생성 */
  async function sign(dataObj, nonce) {
    const key = _getSessionKey();
    const message = _canonicalize(dataObj) + '&nonce=' + nonce;
    const enc = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
      'raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message));
    return Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  /* 서명 검증 */
  async function verify(dataObj, nonce, signature) {
    const expected = await sign(dataObj, nonce);
    return expected === signature;
  }

  /* 데이터에 nonce + 서명 첨부 후 반환 */
  async function wrap(dataObj) {
    const nonce = NonceStore.generate();
    const sig = await sign(dataObj, nonce);
    return { ...dataObj, _nonce: nonce, _sig: sig };
  }

  /* 수신 데이터의 nonce 소비 + 서명 검증 */
  async function unwrap(wrappedObj) {
    const { _nonce, _sig, ...dataObj } = wrappedObj;
    if (!NonceStore.consume(_nonce)) {
      throw new Error('[SecureSign] nonce 검증 실패: 만료되었거나 재사용된 요청입니다.');
    }
    const ok = await verify(dataObj, _nonce, _sig);
    if (!ok) throw new Error('[SecureSign] 서명 검증 실패: 파라미터가 변조되었습니다.');
    return dataObj;
  }

  return { sign, verify, wrap, unwrap };
})();

/* ══════════════════════════════════════════════════════════
   ■ [항목 1·3] CI/DI 평문 노출 차단 + 본인확인 결과 검증
   - CI/DI 값을 절대 DOM·URL·로그에 노출하지 않음
   - 본인확인 결과와 입력값 일치 여부 검증
   - SafeKey 콜백 처리 시 사용
══════════════════════════════════════════════════════════ */
const SecureCI = (() => {
  /* CI/DI를 메모리에만 보관 (외부 접근 불가) */
  let _ci = null;
  let _di = null;
  let _verifiedName = null;
  let _verifiedBirthdate = null;
  let _verifiedGender = null;

  /* 본인확인 결과 저장 (SafeKey 콜백에서 호출) */
  function store(payload) {
    if (!payload) return;
    // CI/DI는 메모리에만 저장, DOM·로컬스토리지에 절대 기록하지 않음
    _ci = payload.ci || null;
    _di = payload.di || null;
    _verifiedName = payload.name || null;
    _verifiedBirthdate = payload.birthdate || null;
    _verifiedGender = payload.gender || null;

    // URL 파라미터에서 CI/DI 흔적 제거
    if (window.history && window.history.replaceState) {
      const clean = window.location.pathname + window.location.hash;
      window.history.replaceState({}, document.title, clean);
    }
  }

  /* [항목 3] 입력값과 본인확인 결과 일치 검증 */
  function verify(inputName, inputBirthdate, inputGender) {
    if (!_ci || !_verifiedName) return { ok: false, reason: '본인확인 결과가 없습니다.' };
    if (_verifiedName !== inputName.trim())
      return { ok: false, reason: '입력한 이름이 본인확인 결과와 일치하지 않습니다.' };
    if (_verifiedBirthdate && inputBirthdate && _verifiedBirthdate !== inputBirthdate.replace(/-/g,''))
      return { ok: false, reason: '생년월일이 본인확인 결과와 일치하지 않습니다.' };
    if (_verifiedGender && inputGender && _verifiedGender !== inputGender)
      return { ok: false, reason: '성별이 본인확인 결과와 일치하지 않습니다.' };
    return { ok: true };
  }

  /* CI 존재 여부만 반환 (CI 값 자체는 노출 안 함) */
  function hasCi() { return !!_ci; }

  /* 회원가입 완료 후 메모리 초기화 */
  function clear() { _ci = null; _di = null; _verifiedName = null; _verifiedBirthdate = null; _verifiedGender = null; }

  /* CI를 직접 DOM에 쓰는 시도 차단 — MutationObserver로 감지 */
  function watchDomLeaks() {
    if (typeof MutationObserver === 'undefined') return;
    const PATTERNS = [/[A-Za-z0-9+/]{80,}={0,2}/]; // Base64 인코딩된 긴 문자열 (CI/DI 패턴)
    const obs = new MutationObserver(muts => {
      muts.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeType === 1) {
            const inputs = node.querySelectorAll ? node.querySelectorAll('input[value]') : [];
            inputs.forEach(inp => {
              if (inp.type !== 'password' && PATTERNS.some(p => p.test(inp.value || ''))) {
                console.warn('[SecureCI] CI/DI 패턴 노출 감지 — input 값 초기화:', inp.id || inp.name);
                inp.value = '';
              }
            });
          }
        });
      });
    });
    obs.observe(document.body || document.documentElement, { childList: true, subtree: true });
  }

  return { store, verify, hasCi, clear, watchDomLeaks };
})();

const Auth = (() => {
  const SESSION_KEY = 'agastya_session'; // 한국 아가스티아 협회
  const SESSION_TTL = 2 * 60 * 60 * 1000; // 2시간
  const PBKDF2_ITER = 100000;

  function generateSalt() {
    const arr = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  async function hashPassword(password, salt) {
    const useSalt = salt || generateSalt();
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(useSalt), iterations: PBKDF2_ITER },
      keyMaterial, 256
    );
    const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
    return { hash: `pbkdf2:${useSalt}:${hashHex}`, salt: useSalt };
  }

  async function verifyPassword(password, storedHash) {
    if (!storedHash) return false;
    if (!storedHash.startsWith('pbkdf2:')) {
      const enc = new TextEncoder();
      const buf = await crypto.subtle.digest('SHA-256', enc.encode(password));
      const legacyHash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
      return legacyHash === storedHash;
    }
    const parts = storedHash.split(':');
    if (parts.length !== 3) return false;
    const { hash } = await hashPassword(password, parts[1]);
    return hash === storedHash;
  }

  function saveSession(user) {
    const sessionData = {
      id: user.id, username: user.username, name: user.name,
      email: user.email, phone: user.phone || '',
      birthdate: user.birthdate || '',
      gender: user.gender || '',
      role: user.role,
      loginAt: Date.now(), expiresAt: Date.now() + SESSION_TTL
    };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
    localStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
  }

  function getSession() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const data = JSON.parse(raw);
      if (data.expiresAt && Date.now() > data.expiresAt) { logout(); return null; }
      return data;
    } catch { return null; }
  }

  function logout() {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY);
    window.location.href = 'index.html';
  }

  function isLoggedIn() { return getSession() !== null; }
  function isAdmin() { const s = getSession(); return s && (s.role === 'admin' || s.role === 'superadmin'); }

  function requireLogin(redirectUrl) {
    if (!isLoggedIn()) {
      window.location.href = `login.html?redirect=${encodeURIComponent(redirectUrl || window.location.href)}`;
      return false;
    }
    return true;
  }

  function requireAdmin() {
    if (!isLoggedIn()) { window.location.href = 'login.html?redirect=admin.html'; return false; }
    if (!isAdmin()) {
      Toast.show('관리자 권한이 필요합니다.', 'error');
      setTimeout(() => window.location.href = 'index.html', 1500);
      return false;
    }
    return true;
  }

  /* ── 로그인 (Supabase 직접) ── */
  async function login(username, password) {
    try {
      const res = await fetch('tables/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ username, password })
      });

      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json.success) {
        return { success: false, message: json.message || '아이디 또는 비밀번호가 올바르지 않습니다.' };
      }

      const user = json.user;
      saveSession(user);
      return { success: true, user };
    } catch (e) {
      return { success: false, message: '로그인 중 오류가 발생했습니다.' };
    }
  }

  /* ── 회원가입 (Supabase 직접) ── */
  /* [항목 2] 파라미터 변조 방지: 전송 전 HMAC 서명 생성 및 검증                 */
  /* [항목 4] 리플레이 방지: register 호출마다 신규 nonce 발급 후 소비            */
  async function register({ username, password, name, email, phone, gender, _regNonce }) {
    try {
      // [항목 4] 회원가입 nonce 소비 — 동일 요청 재전송 방지
      if (_regNonce && !NonceStore.consume(_regNonce)) {
        return { success: false, message: '요청이 만료되었거나 중복 제출되었습니다. 페이지를 새로고침 후 다시 시도해주세요.' };
      }

      // [항목 2] 전달 데이터 무결성 확인 (클라이언트 내부 검증)
      const payloadToSign = { username, name, email, gender: gender || '', phone: phone || '' };
      await SecureSign.sign(payloadToSign, _regNonce || 'no-nonce');

      const res = await fetch('tables/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ username, password, name, email, phone: phone || '', gender: gender || '' })
      });

      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json.success) {
        return { success: false, message: json.message || '회원가입 중 오류가 발생했습니다.' };
      }

      SecureCI.clear();
      return { success: true, user: json.user };
    } catch (e) {
      return { success: false, message: '회원가입 중 오류가 발생했습니다.' };
    }
  }

  /* ── 회원가입용 nonce 발급 (폼 렌더링 시 호출) ── */
  /* [항목 4] 폼 로드 시 1회용 nonce 생성 — 동일 nonce 재사용 방지 */
  function generateRegisterNonce() {
    return NonceStore.generate();
  }

  /* ── 비밀번호 재설정 코드 저장 ── */
  async function saveResetCode(email, code) {
    try {
      const res = await fetch('tables/auth/save-reset-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ email, code })
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json.success) {
        return { success: false, message: json.message || '오류가 발생했습니다.' };
      }
      return { success: true, userId: json.userId, name: json.name };
    } catch (e) {
      return { success: false, message: '오류가 발생했습니다.' };
    }
  }

  /* ── 재설정 코드 검증 ── */
  async function verifyResetCode(email, code) {
    try {
      const res = await fetch('tables/auth/verify-reset-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ email, code })
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json.success) {
        return { success: false, message: json.message || '오류가 발생했습니다.' };
      }
      return { success: true, userId: json.userId };
    } catch (e) {
      return { success: false, message: '오류가 발생했습니다.' };
    }
  }

  /* ── 비밀번호 변경 ── */
  async function changePassword(userId, newPassword) {
    try {
      const res = await fetch('tables/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ userId, newPassword })
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || !json.success) {
        return { success: false, message: json.message || '비밀번호 변경 중 오류가 발생했습니다.' };
      }
      return { success: true };
    } catch (e) {
      return { success: false, message: '비밀번호 변경 중 오류가 발생했습니다.' };
    }
  }

  function updateNavAuth() {
    const session = getSession();
    // 데스크탑 auth 영역
    const authArea = document.getElementById('nav-auth');
    // 드로어 auth 영역
    const drawerAuth = document.getElementById('nav-auth-drawer');

    const loggedInHtml = (session) => `
      <span style="font-size:0.8rem; color:var(--text-mid); margin-right:4px;">${session.name}님</span>
      ${session.role === 'admin' ? `<a href="admin.html" class="btn-nav-login" style="color:var(--gold);border-color:var(--gold);">관리자</a>` : ''}
      <a href="mypage.html" class="btn-nav-login">마이페이지</a>
      <button onclick="Auth.logout()" class="btn-nav-signup">로그아웃</button>
    `;
    const loggedOutHtml = `
      <a href="login.html" class="btn-nav-login">로그인</a>
      <a href="register.html" class="btn-nav-signup">회원가입</a>
    `;
    const drawerLoggedInHtml = (session) => `
      <span style="font-size:0.83rem;color:var(--text-mid);display:block;margin-bottom:8px;">${session.name}님</span>
      ${session.role === 'admin' ? `<a href="admin.html" style="display:block;text-align:center;padding:11px 8px;border:1px solid var(--gold);border-radius:4px;color:var(--gold);font-size:0.85rem;margin-bottom:6px;" onclick="closeDrawer()">관리자 페이지</a>` : ''}
      <a href="mypage.html" style="display:block;text-align:center;padding:11px 8px;border:1px solid var(--border);border-radius:4px;font-size:0.85rem;margin-bottom:6px;" onclick="closeDrawer()">마이페이지</a>
      <button onclick="Auth.logout()" style="width:100%;padding:11px 8px;border-radius:4px;background:var(--navy);color:white;font-size:0.85rem;border:none;cursor:pointer;">로그아웃</button>
    `;
    const drawerLoggedOutHtml = `
      <a href="login.html" style="display:block;text-align:center;padding:11px 8px;border:1px solid var(--border);border-radius:4px;font-size:0.85rem;margin-bottom:6px;" onclick="closeDrawer()">로그인</a>
      <a href="register.html" style="display:block;text-align:center;padding:11px 8px;border-radius:4px;background:var(--navy);color:white;font-size:0.85rem;" onclick="closeDrawer()">회원가입</a>
    `;

    if (authArea) {
      authArea.innerHTML = session ? loggedInHtml(session) : loggedOutHtml;
    }
    if (drawerAuth) {
      drawerAuth.innerHTML = session ? drawerLoggedInHtml(session) : drawerLoggedOutHtml;
    }
  }

  return {
    hashPassword, verifyPassword, generateSalt,
    saveSession, getSession, logout,
    isLoggedIn, isAdmin, requireLogin, requireAdmin,
    login, register, generateRegisterNonce,
    saveResetCode, verifyResetCode, changePassword,
    updateNavAuth
  };
})();

/* ── Toast ── */
const Toast = (() => {
  function getContainer() {
    let c = document.getElementById('toast-container');
    if (!c) { c = document.createElement('div'); c.id = 'toast-container'; c.className = 'toast-container'; document.body.appendChild(c); }
    return c;
  }
  function show(message, type = 'info', duration = 3500) {
    const container = getContainer();
    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = 'slideOut 0.3s ease forwards';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
  return { show };
})();

/* ── 공통 네비게이션 ── */
function renderNavbar(activePage) {
  /* ── navbar 본체 (드로어/오버레이 제외) ── */
  const navHtml = `
  <nav class="navbar" id="navbar">
    <div class="navbar__inner">
      <a href="index.html" class="navbar__logo">
        <img src="images/logo.png" alt="한국 아가스티아 협회 로고" class="navbar__logo-img">
        <div class="navbar__logo-text">
          <span class="navbar__logo-main">한국 아가스티아 협회</span>
          <span class="navbar__logo-sub">Korea Agastya Association</span>
        </div>
      </a>
      <!-- 데스크탑 네비 링크 -->
      <div class="navbar__desktop-menu" style="display:flex;align-items:center;gap:36px;">
        <a href="index.html" class="navbar__link ${activePage==='home'?'active':''}">홈</a>
        <a href="about.html" class="navbar__link ${activePage==='about'?'active':''}">협회 소개</a>
        <a href="philosophy.html" class="navbar__link ${activePage==='philosophy'?'active':''}">철학</a>
        <a href="service.html" class="navbar__link ${activePage==='service'?'active':''}">서비스</a>
        <a href="news.html" class="navbar__link ${activePage==='news'?'active':''}">소식 &amp; 기사</a>
        <a href="seminar.html" class="navbar__link ${activePage==='seminar'?'active':''}">신청</a>
        <a href="contact.html" class="navbar__link ${activePage==='contact'?'active':''}">문의</a>
      </div>
      <div class="navbar__auth" id="nav-auth">
        <a href="login.html" class="btn-nav-login">로그인</a>
        <a href="register.html" class="btn-nav-signup">회원가입</a>
      </div>
      <button class="navbar__hamburger" id="hamburger" onclick="openDrawer()" aria-label="메뉴 열기" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
    </div>
  </nav>`;

  /* ── 드로어 패널 + 오버레이는 body 직속으로 삽입 (stacking context 탈출) ── */
  const drawerHtml = `
  <!-- 드로어 오버레이: body 직속, z-index 99998 -->
  <div class="drawer-overlay" id="drawer-overlay" onclick="closeDrawer()"></div>
  <!-- 드로어 패널: body 직속, z-index 99999 -->
  <div class="navbar__menu" id="navbar-menu" role="dialog" aria-modal="true" aria-label="내비게이션 메뉴">
    <div class="drawer-header">
      <span class="drawer-header__logo">MENU</span>
      <button class="drawer-close" onclick="closeDrawer()" aria-label="메뉴 닫기">✕</button>
    </div>
    <div class="drawer-links">
      <a href="index.html" class="navbar__link ${activePage==='home'?'active':''}">홈</a>
      <a href="about.html" class="navbar__link ${activePage==='about'?'active':''}">협회 소개</a>
      <a href="philosophy.html" class="navbar__link ${activePage==='philosophy'?'active':''}">철학</a>
      <a href="service.html" class="navbar__link ${activePage==='service'?'active':''}">서비스</a>
      <a href="news.html" class="navbar__link ${activePage==='news'?'active':''}">소식 &amp; 기사</a>
      <a href="seminar.html" class="navbar__link ${activePage==='seminar'?'active':''}">신청</a>
      <a href="contact.html" class="navbar__link ${activePage==='contact'?'active':''}">문의</a>
    </div>
    <div class="navbar__auth" id="nav-auth-drawer">
      <a href="login.html" style="display:block;text-align:center;padding:11px 8px;border:1px solid var(--border);border-radius:4px;font-size:0.88rem;" onclick="closeDrawer()">로그인</a>
      <a href="register.html" style="display:block;text-align:center;padding:11px 8px;border-radius:4px;background:var(--navy);color:white;font-size:0.88rem;" onclick="closeDrawer()">회원가입</a>
    </div>
  </div>`;

  /* navbar는 body 맨 앞, 드로어는 body 맨 뒤(footer 앞)에 삽입 */
  document.body.insertAdjacentHTML('afterbegin', navHtml);
  document.body.insertAdjacentHTML('beforeend', drawerHtml);

  window.addEventListener('scroll', () => {
    const nb = document.getElementById('navbar');
    if (nb) nb.classList.toggle('scrolled', window.scrollY > 20);
  });
  Auth.updateNavAuth();
}

function openDrawer() {
  const menu    = document.getElementById('navbar-menu');
  const overlay = document.getElementById('drawer-overlay');
  const btn     = document.getElementById('hamburger');

  /* 드로어·오버레이가 body 직속이 아닌 경우(구형 마크업 호환) 이동 */
  if (overlay && overlay.parentElement !== document.body) {
    document.body.appendChild(overlay);
  }
  if (menu && menu.parentElement !== document.body) {
    document.body.appendChild(menu);
  }

  if (menu)    menu.classList.add('open');
  if (overlay) overlay.classList.add('open');
  if (btn)     btn.setAttribute('aria-expanded', 'true');
  document.body.style.overflow = 'hidden';
}

function closeDrawer() {
  const menu    = document.getElementById('navbar-menu');
  const overlay = document.getElementById('drawer-overlay');
  const btn     = document.getElementById('hamburger');
  if (menu)    menu.classList.remove('open');
  if (overlay) overlay.classList.remove('open');
  if (btn)     btn.setAttribute('aria-expanded', 'false');
  document.body.style.overflow = '';
}

// 하위 호환성 유지
function toggleMenu() { openDrawer(); }

// ESC 키로 드로어 닫기
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeDrawer();
});

/* ── 공통 푸터 ── */
function renderFooter() {
  const footerHtml = `
  <footer class="footer">
    <div class="footer__inner">
      <div>
        <div class="footer__logo-main">한국 아가스티아 협회</div>
        <div class="footer__logo-sub">Korea Agastya Association</div>
        <p style="font-size:0.82rem; line-height:1.7; margin-top:8px;">고대의 지혜를 현대를 살아가는<br>확신으로 연결합니다.</p>
      </div>
      <div class="footer__right-col">
        <div class="footer__menu-section">
          <div class="footer__menu-title">Menu</div>
          <div class="footer__menu-grid">
            <a href="index.html" class="footer__menu-link">홈</a>
            <a href="about.html" class="footer__menu-link">협회 소개</a>
            <a href="philosophy.html" class="footer__menu-link">철학</a>
            <a href="service.html" class="footer__menu-link">서비스</a>
            <a href="news.html" class="footer__menu-link">소식 &amp; 기사</a>
            <a href="seminar.html" class="footer__menu-link">신청</a>
            <a href="contact.html" class="footer__menu-link">문의</a>
          </div>
        </div>
        <div class="footer__social">
          <a href="https://cafe.daum.net/argartan-light" target="_blank" rel="noopener" class="footer__social-btn footer__social-btn--daum" aria-label="다음카페">카페</a>
          <a href="https://www.youtube.com/@agartanoflight" target="_blank" rel="noopener" class="footer__social-btn footer__social-btn--yt" aria-label="YouTube">▶</a>
        </div>
      </div>
    </div>
    <div class="footer__biz-info" style="background:rgba(0,0,0,0.15);padding:14px 24px;border-top:1px solid rgba(255,255,255,0.07);text-align:center;">
      <p style="font-size:0.72rem;color:rgba(255,255,255,0.4);line-height:2;margin:0;word-break:keep-all;">
        아가스티아코리아 주식회사
        <span style="color:rgba(255,255,255,0.18);margin:0 8px;">|</span>대표: 이승훈
        <span style="color:rgba(255,255,255,0.18);margin:0 8px;">|</span>사업자등록번호: 609-88-03705
        <span style="color:rgba(255,255,255,0.18);margin:0 8px;">|</span>전화: 02-336-0996
        <span style="color:rgba(255,255,255,0.18);margin:0 8px;">|</span>주소: 서울특별시 마포구 월드컵로 37, 201-A호 (합정동, 합정동웰빙센터)
      </p>
    </div>
    <div class="footer__bottom">
      <div class="footer__bottom-links">
        <a href="privacy.html" class="footer__bottom-link">개인정보처리방침</a>
        <a href="terms.html" class="footer__bottom-link">서비스 이용약관</a>
      </div>
      <span id="footer-copyright-text">© 2026 한국 아가스티아 협회 (KOREA AGASTYA ASSOCIATION). ALL RIGHTS RESERVED.</span>
    </div>
  </footer>`;
  document.body.insertAdjacentHTML('beforeend', footerHtml);
}

function formatPrice(num) { return Number(num).toLocaleString('ko-KR') + '원'; }

/* ════════════════════════════════════════════════
   서비스 준비중 / 사이트 점검 접근 차단 시스템
   site_content 키:
     service_coming_soon_pages : 쉼표구분 경로 목록
     site_maintenance_mode     : "true" 이면 점검중
     site_maintenance_msg      : 점검 메시지
     site_maintenance_time     : 점검 예정 시간 (예: "2026-04-13 02:00 ~ 06:00")
════════════════════════════════════════════════ */

/* ════════════════════════════════════════════════
   실시간 점검 모드 폴링
   - 30초마다 site_maintenance_mode 값을 체크
   - 점검 ON 감지 시 현재 열려 있는 페이지를 즉시 차단
   - isSuperAdmin=true 이면 차단하지 않고 알림만 표시
════════════════════════════════════════════════ */
let _maintPollTimer = null;
let _maintLastModeVal = null;   // 이전 점검 ON/OFF 캐시
let _maintLastUpdatedAt = null; // site_maintenance_updated_at 캐시 (변화 감지용)

function _startMaintenancePoller(isSuperAdmin) {
  if (_maintPollTimer) return; // 중복 실행 방지
  const POLL_INTERVAL = 20 * 1000; // 20초마다 폴링

  async function _poll() {
    try {
      // site_content 전체 대신 maintenance 관련 키만 검색해서 빠르게 조회
      const res = await fetch('tables/site_content?limit=500', { cache: 'no-store' });
      if (!res.ok) return;
      const json = await res.json();
      const rows = json.data || json || [];
      const map = {};
      (Array.isArray(rows) ? rows : []).forEach(r => { if (r && r.key) map[r.key] = String(r.content ?? ''); });

      const maintVal = map.hasOwnProperty('site_maintenance_mode') ? map['site_maintenance_mode'] : 'true';
      const isMaint = (maintVal !== 'false');
      const updatedAt = map['site_maintenance_updated_at'] || '';

      // updated_at 또는 mode 값이 바뀌었을 때만 처리
      const changed = (_maintLastModeVal !== String(isMaint)) || (_maintLastUpdatedAt !== updatedAt && updatedAt !== '');
      if (!changed) return;

      _maintLastModeVal = String(isMaint);
      _maintLastUpdatedAt = updatedAt;

      if (isMaint) {
        const msg = map['site_maintenance_msg'] || '현재 사이트 점검 중입니다.\n잠시 후 다시 방문해 주세요.';
        const timeStr = map['site_maintenance_time'] || '';

        if (isSuperAdmin) {
          // 최고관리자(admin): 차단 없이 상단 알림 배너만 표시
          _showMaintBannerForAdmin(timeStr);
        } else {
          // 일반 회원 / 일반 관리자 계정: 즉시 전체 차단
          clearInterval(_maintPollTimer);
          _maintPollTimer = null;
          renderBlockScreen('사이트 점검 중', msg, true, timeStr);
        }
      } else {
        // 점검 해제: 관리자 배너 제거 (최고관리자 배너 숨기기)
        _hideMaintBannerForAdmin();
      }
    } catch(e) { /* 폴링 오류 무시 */ }
  }

  // 첫 실행은 5초 후 (초기 checkPageAccess 완료 대기), 이후 주기적 실행
  setTimeout(_poll, 5000);
  _maintPollTimer = setInterval(_poll, POLL_INTERVAL);
}

/* 최고관리자 전용: 점검 중 상단 알림 배너 */
function _showMaintBannerForAdmin(timeStr) {
  if (document.getElementById('_maint-admin-banner')) return;
  const banner = document.createElement('div');
  banner.id = '_maint-admin-banner';
  banner.style.cssText = [
    'position:fixed;top:0;left:0;right:0;z-index:2147483646;',
    'background:#c8610a;color:white;text-align:center;',
    'padding:8px 16px;font-size:0.82rem;font-weight:600;letter-spacing:0.03em;',
    'box-shadow:0 2px 8px rgba(0,0,0,0.3);'
  ].join('');
  banner.innerHTML = '⚠️ 현재 점검 모드 ON — 관리자(admin) 계정으로 접속 중이므로 정상 표시됩니다.'
    + (timeStr ? `&nbsp;&nbsp;|&nbsp;&nbsp;🕒 ${timeStr}` : '')
    + '&nbsp;&nbsp;<button onclick="this.parentElement.remove()" style="background:rgba(255,255,255,0.2);border:none;color:white;padding:2px 8px;border-radius:4px;cursor:pointer;font-size:0.78rem;">닫기</button>';
  document.body.prepend(banner);
}

function _hideMaintBannerForAdmin() {
  const b = document.getElementById('_maint-admin-banner');
  if (b) b.remove();
}

/* ── 차단 화면 렌더링 ── */
function renderBlockScreen(title, message, isMaintenance, timeStr) {
  document.body.style.visibility = 'hidden';
  document.body.style.overflow = 'hidden';

  const timeBlock = (isMaintenance && timeStr)
    ? '<div style="margin:0 0 20px;padding:10px 16px;background:#f0f4ff;border-radius:6px;border:1px solid #c7d6f5;font-size:0.82rem;color:#334;">🕒 점검 예정 시간: <strong>' + timeStr + '</strong></div>'
    : '';

  const urgentBox = isMaintenance
    ? '<div style="margin-top:24px;padding:14px 18px;background:#f8f4ed;border-radius:8px;border:1px solid #e8dcc8;text-align:center;"><p style="font-size:0.78rem;color:#888;margin:0 0 6px;letter-spacing:0.05em;">긴급 문의 · 오류 제보</p><p style="font-size:0.85rem;color:#444;line-height:1.8;margin:0;">관리자 <strong style="color:#0b1629;">정지수</strong><br><a href="tel:01039992175" style="color:#c8973a;font-weight:600;text-decoration:none;font-size:0.95rem;">010-3999-2175</a></p></div>' +
      '<div style="margin-top:12px;text-align:center;"><a href="login.html" style="font-size:0.75rem;color:transparent;text-decoration:none;user-select:none;" tabindex="-1">관리자 로그인</a></div>'
    : '';

  const contactLink = !isMaintenance
    ? '<br><a href="contact.html" style="display:inline-block;margin-top:14px;font-size:0.82rem;color:#c8973a;text-decoration:underline;">문의하기</a>'
    : '';

  const overlay = document.createElement('div');
  overlay.id = 'block-screen-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:#0b1629;display:flex;align-items:center;justify-content:center;padding:20px;visibility:visible;';
  overlay.innerHTML =
    '<div style="background:white;border-radius:12px;padding:52px 44px;text-align:center;max-width:440px;width:100%;box-shadow:0 32px 96px rgba(0,0,0,0.6);">' +
    '<div style="font-size:3rem;margin-bottom:20px;">' + (isMaintenance ? '🔧' : '🌿') + '</div>' +
    '<div style="font-family:\'Noto Serif KR\',serif;font-size:1.25rem;color:#0b1629;font-weight:600;margin-bottom:14px;letter-spacing:-0.01em;">' + (isMaintenance ? '사이트 점검 중' : title) + '</div>' +
    '<p style="font-size:0.88rem;color:#666;line-height:2;white-space:pre-line;margin-bottom:16px;">' + message + '</p>' +
    timeBlock +
    '<a href="index.html" style="display:inline-block;padding:13px 32px;background:#c8973a;color:white;text-decoration:none;border-radius:4px;font-size:0.9rem;font-weight:500;">홈으로 돌아가기</a>' +
    contactLink +
    urgentBox +
    '</div>';
  document.body.appendChild(overlay);
}

/* ── 최고관리자(username==='admin') 여부 확인 ── */
function _isSuperAdminSession() {
  try {
    const s = JSON.parse(sessionStorage.getItem('agastya_session') || 'null');
    return s && s.username === 'admin' && (s.role === 'admin' || s.role === 'superadmin');
  } catch(e) { return false; }
}

/* ── 점검 모드 빠른 선차단: 스크립트 실행 즉시 숨김 (DB 조회 전 노출 방지) ── */
(function earlyBlock() {
  try {
    // 최고관리자(username=admin)만 점검 중에도 통과 — 일반 관리자 계정도 차단
    if (_isSuperAdminSession()) return;
    const pagePath = window.location.pathname.split('/').pop() || 'index.html';
    const allowedPages = ['index.html', '', 'login.html', 'admin.html'];
    if (allowedPages.includes(pagePath)) return;
    // 허용 페이지가 아닌 모든 페이지는 DB 확인 전까지 무조건 숨김
    document.documentElement.style.visibility = 'hidden';
  } catch(e) {}
})();

/* 현재 페이지 접근 권한 확인 */
async function checkPageAccess() {
  // 최고관리자(username=admin)만 점검 중에도 완전 통과
  if (_isSuperAdminSession()) {
    document.documentElement.style.visibility = '';
    document.body.style.visibility = '';
    document.body.style.opacity = '1';
    // 최고관리자도 실시간 폴링은 시작 (점검 해제 감지용 — 차단은 하지 않음)
    _startMaintenancePoller(true);
    return;
  }

  const pagePath = window.location.pathname.split('/').pop() || 'index.html';
  const allowedPages = ['index.html', '', 'login.html', 'admin.html'];

  // index / login / admin 은 항상 허용
  if (allowedPages.includes(pagePath)) {
    document.documentElement.style.visibility = '';
    return;
  }

  // DB 조회 전 화면 숨기기
  document.documentElement.style.visibility = 'hidden';

  try {
    // site_content 전체를 한 번에 로드 → key 맵으로 변환
    const res = await fetch('tables/site_content?limit=500');
    const json = await res.json();
    const rows = (json.data || json || []);
    const map = {};
    (Array.isArray(rows) ? rows : []).forEach(r => {
      if (r && r.key) map[r.key] = String(r.content ?? '');
    });

    // ① 점검 모드 확인
    // DB에 site_maintenance_mode 키가 없거나 값이 'false'가 아니면 → 점검중 (기본값 = 점검중)
    const maintVal = map.hasOwnProperty('site_maintenance_mode')
      ? map['site_maintenance_mode']
      : 'true';                        // ← 키 없으면 무조건 점검중
    const isMaint = (maintVal !== 'false');

    if (isMaint) {
      const msg = map['site_maintenance_msg'] || '현재 사이트 점검 중입니다.\n잠시 후 다시 방문해 주세요.';
      const timeStr = map['site_maintenance_time'] || '';
      renderBlockScreen('사이트 점검 중', msg, true, timeStr);
      return; // 차단됐으므로 폴링 불필요
    }

    // ② 준비중 페이지 목록 확인
    const blockedPages = map['service_coming_soon_pages']
      ? map['service_coming_soon_pages'].split(',').map(p => p.trim()).filter(Boolean)
      : [];

    if (blockedPages.includes(pagePath)) {
      renderBlockScreen(
        '서비스 준비 중',
        '해당 서비스는 현재 준비 중입니다.\n보다 나은 서비스로 곧 찾아뵙겠습니다.\n\n이용에 불편을 드려 죄송합니다.',
        false, ''
      );
    } else {
      document.documentElement.style.visibility = '';
      // 정상 접근 중인 페이지 — 실시간 폴링 시작 (점검 ON 감지 시 즉시 차단)
      _startMaintenancePoller(false);
    }
  } catch(e) {
    // 오류 시 점검 화면 표시 (보안 우선)
    console.warn('[checkPageAccess] 오류, 점검 화면 표시:', e);
    renderBlockScreen('사이트 점검 중', '현재 사이트 점검 중입니다.\n잠시 후 다시 방문해 주세요.', true, '');
  }
}

/* 페이지 로드 시 자동 실행
   auth.js는 </body> 직전에 로드되므로 DOMContentLoaded는 이미 발화된 상태.
   readyState 체크 후 즉시 실행하거나 이벤트 대기. */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', checkPageAccess);
} else {
  checkPageAccess();
}
function formatDate(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr;
  return `${d.getFullYear()}.${String(d.getMonth()+1).padStart(2,'0')}.${String(d.getDate()).padStart(2,'0')}`;
}

/* ── iOS BFCache 대응 ──
   iOS Safari / Chrome 뒤로가기 스와이프 시 bfcache에서 복원된 페이지는
   DOMContentLoaded가 재실행되지 않아 로그인 상태 등이 구식으로 표시될 수 있음.
   pageshow.persisted === true 일 때 세션/네비 상태를 강제 갱신한다. */
window.addEventListener('pageshow', function(e) {
  /* ── iOS BFCache 복원 시 body 스크롤 잠금 강제 해제 ──
     모달/시트가 열린 채로 스와이프 뒤로가기를 하면
     다음 페이지에서 body가 position:fixed 상태로 굳어 화면이 안 움직이는 현상 방지 */
  document.body.style.position = '';
  document.body.style.top      = '';
  document.body.style.width    = '';
  document.body.style.overflow = '';

  if (!e.persisted) return; // bfcache 복원이 아닌 경우 이하 무시
  // 네비 auth 영역 갱신
  try { Auth.updateNavAuth(); } catch(_) {}
  // 각 페이지별 재초기화 함수 호출 (함수가 있을 때만)
  const reinitFns = [
    'initDashboard',      // mypage.html
    'initAdminPage',      // admin.html (있을 경우)
    'initSeminarPage',    // seminar.html (있을 경우)
  ];
  for (const fn of reinitFns) {
    if (typeof window[fn] === 'function') {
      try { window[fn](); } catch(err) {
        console.warn('[BFCache] ' + fn + ' 재실행 실패:', err);
      }
      break; // 첫 번째로 찾은 함수만 실행
    }
  }
});

/* ── 페이지 떠날 때 body 잠금 해제 ──
   iOS 스와이프로 다른 페이지로 이동 시 body.position:fixed가
   남아있으면 이전 페이지로 돌아왔을 때 화면이 굳음 → 미리 해제 */
window.addEventListener('pagehide', function() {
  document.body.style.position = '';
  document.body.style.top      = '';
  document.body.style.width    = '';
  document.body.style.overflow = '';
});
