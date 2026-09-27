'use strict';

/* =====================================================================
   Shared script for ALL pages.
   Storage: localStorage (works without a server).
     sf_users   -> array of accounts { id, name, email, salt, hash, createdAt }
     sf_session -> currently logged-in user { id, email, name }
     sf_theme   -> "dark" | "light"
     sf_data_<userId> -> that user's saved workouts/progress (see SF.loadData / SF.saveData)
   ===================================================================== */
const SF = (() => {
  const KEYS = { users: 'sf_users', session: 'sf_session', theme: 'sf_theme' };
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  const MIN_PASSWORD = 8;

  /* ---------- storage helpers ---------- */
  const read = (key, fallback) => {
    try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : fallback; }
    catch { return fallback; }
  };
  const write = (key, value) => {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; }
    catch { return false; }
  };

  /* ---------- password hashing (PBKDF2 + random salt) ---------- */
  const toHex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

  async function hashPassword(password, salt) {
    if (!(window.crypto && crypto.subtle)) {
      throw new Error('Secure context required. Open the site via localhost (e.g. VS Code Live Server).');
    }
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
    return toHex(new Uint8Array(bits));
  }

  const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
  const isValidEmail = (email) => EMAIL_RE.test(normalizeEmail(email));

  /* ---------- accounts ---------- */
  const getUsers = () => read(KEYS.users, []);

  /** Used by signup.html later: SF.registerUser({ name, email, password }) */
  async function registerUser({ name = '', email, password }) {
    email = normalizeEmail(email);
    if (!isValidEmail(email)) return { ok: false, error: 'Enter a valid email address.' };
    if (String(password || '').length < MIN_PASSWORD) {
      return { ok: false, error: `Password must be at least ${MIN_PASSWORD} characters.` };
    }
    const users = getUsers();
    if (users.some(u => u.email === email)) return { ok: false, error: 'An account with this email already exists.' };

    try {
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const salt = toHex(saltBytes);
      const user = {
        id: 'u_' + Date.now().toString(36) + toHex(saltBytes.slice(0, 3)),
        name: String(name).trim(), email, salt,
        hash: await hashPassword(password, salt),
        createdAt: new Date().toISOString()
      };
      users.push(user);
      if (!write(KEYS.users, users)) return { ok: false, error: 'Could not save the account. Check that browser storage is enabled.' };
      return { ok: true, user: { id: user.id, email: user.email, name: user.name } };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  async function login(email, password) {
    email = normalizeEmail(email);
    const genericError = { ok: false, error: 'Incorrect email or password.' };
    const user = getUsers().find(u => u.email === email);
    if (!user) return genericError;
    try {
      const hash = await hashPassword(password, user.salt);
      if (hash !== user.hash) return genericError;
    } catch (err) {
      return { ok: false, error: err.message };
    }
    const session = { id: user.id, email: user.email, name: user.name };
    if (!write(KEYS.session, session)) return { ok: false, error: 'Could not start a session. Check that browser storage is enabled.' };
    return { ok: true, user: session };
  }

  function currentUser() {
    const s = read(KEYS.session, null);
    if (!s) return null;
    return getUsers().some(u => u.id === s.id) ? s : null; // session is valid only if the account still exists
  }

  function logout() {
    try { localStorage.removeItem(KEYS.session); } catch { /* ignore */ }
    location.replace('index.html');
  }

  /* ---------- per-user saved data (workout programs & logged workouts) ---------- */
  const emptyData = () => ({ programs: [], workouts: [], goal: null, customExercises: [] });
  const loadData = () => {
    const u = currentUser();
    if (!u) return emptyData();
    const data = read('sf_data_' + u.id, null) || emptyData();
    if (!Array.isArray(data.programs)) data.programs = [];
    if (!Array.isArray(data.workouts)) data.workouts = [];
    if (!('goal' in data)) data.goal = null;
    if (!Array.isArray(data.customExercises)) data.customExercises = [];
    return data;
  };
  const saveData = (data) => { const u = currentUser(); return u ? write('sf_data_' + u.id, data) : false; };

  /* ---------- page guard: <body data-auth="guest|required"> ---------- */
  function guard() {
    const mode = document.body.dataset.auth;
    const user = currentUser();
    if (mode === 'guest' && user) location.replace('home.html');
    if (mode === 'required' && !user) location.replace('index.html');
  }

  /* ---------- theme ---------- */
  const ICONS = {
    dark:  { src: 'Sun.jpeg', alt: 'Sun',  label: 'Switch to light theme' }, // shown in dark theme
    light: { src: 'dark.png', alt: 'Moon', label: 'Switch to dark theme' }   // shown in light theme
  };

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(KEYS.theme, theme); } catch { /* ignore */ }
    const btn = document.getElementById('theme-toggle');
    const img = document.getElementById('theme-toggle-img');
    if (!btn || !img) return;
    img.src = ICONS[theme].src;
    img.alt = ICONS[theme].alt;
    btn.setAttribute('aria-label', ICONS[theme].label);
    btn.title = ICONS[theme].label;
  }

  function initTheme() {
    applyTheme(document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.addEventListener('click', () => {
      applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
    });
  }

  return { registerUser, login, logout, currentUser, loadData, saveData, guard, initTheme, isValidEmail, MIN_PASSWORD };
})();

/* =====================================================================
   signin.html
   ===================================================================== */
function initSignin() {
  const form = document.getElementById('signin-form');
  if (!form) return;

  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const emailErr = document.getElementById('email-error');
  const passErr = document.getElementById('password-error');
  const message = document.getElementById('form-message');
  const button = document.getElementById('signin-btn');

  const setMessage = (text, info = false) => {
    message.textContent = text;
    message.classList.toggle('is-info', info);
  };
  const setError = (input, target, text) => {
    target.textContent = text;
    input.setAttribute('aria-invalid', text ? 'true' : 'false');
  };

  // Shown after signup.html redirects here with ?registered=1
  if (new URLSearchParams(location.search).get('registered') === '1') {
    setMessage('Account created. Sign in to continue.', true);
  }

  email.addEventListener('input', () => { setError(email, emailErr, ''); setMessage(''); });
  password.addEventListener('input', () => { setError(password, passErr, ''); setMessage(''); });

  document.getElementById('forgot-link').addEventListener('click', (e) => {
    e.preventDefault();
    setMessage('Password recovery is coming soon.', true);
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    setMessage('');

    let valid = true;
    if (!SF.isValidEmail(email.value)) { setError(email, emailErr, 'Enter a valid email address.'); valid = false; }
    if (!password.value) { setError(password, passErr, 'Enter your password.'); valid = false; }
    if (!valid) {
      (email.getAttribute('aria-invalid') === 'true' ? email : password).focus();
      return;
    }

    button.disabled = true;
    const result = await SF.login(email.value, password.value);
    if (result.ok) {
      location.replace('home.html');
    } else {
      setMessage(result.error);
      button.disabled = false;
    }
  });
}

/* =====================================================================
   signup.html
   ===================================================================== */

/* Welcome email is sent through EmailJS (https://www.emailjs.com) - it works
   without your own server. Fill in the 3 values below (see setup steps).
   While they are empty the account is still created, only the email is skipped. */
const EMAIL_CONFIG = {
  serviceId: '',   // e.g. 'service_abc123'
  templateId: '',  // e.g. 'template_xyz789'
  publicKey: ''    // e.g. 'AbCdEfGh123456'
};

async function sendWelcomeEmail(email) {
  const { serviceId, templateId, publicKey } = EMAIL_CONFIG;
  if (!serviceId || !templateId || !publicKey) return { ok: false, skipped: true };

  try {
    const request = fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      keepalive: true, // request finishes even if the page redirects
      body: JSON.stringify({
        service_id: serviceId,
        template_id: templateId,
        user_id: publicKey,
        template_params: { to_email: email, created_at: new Date().toLocaleString() }
      })
    });
    // Do not keep the user waiting more than 4 seconds
    const response = await Promise.race([request, new Promise(resolve => setTimeout(() => resolve(null), 4000))]);
    return { ok: !response || response.ok };
  } catch (err) {
    console.warn('Welcome email was not sent:', err);
    return { ok: false };
  }
}

function initSignup() {
  const form = document.getElementById('signup-form');
  if (!form) return;

  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const confirm = document.getElementById('confirm');
  const emailErr = document.getElementById('email-error');
  const passErr = document.getElementById('password-error');
  const confirmErr = document.getElementById('confirm-error');
  const message = document.getElementById('form-message');
  const button = document.getElementById('signup-btn');

  const setError = (input, target, text) => {
    target.textContent = text;
    input.setAttribute('aria-invalid', text ? 'true' : 'false');
  };

  [[email, emailErr], [password, passErr], [confirm, confirmErr]].forEach(([input, target]) => {
    input.addEventListener('input', () => { setError(input, target, ''); message.textContent = ''; });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    message.textContent = '';

    const checks = [
      [email, emailErr, SF.isValidEmail(email.value) ? '' : 'Enter a valid email address.'],
      [password, passErr, password.value.length >= SF.MIN_PASSWORD ? '' : `Password must be at least ${SF.MIN_PASSWORD} characters.`],
      [confirm, confirmErr, !confirm.value ? 'Confirm your password.' : (confirm.value !== password.value ? 'Passwords do not match.' : '')]
    ];
    checks.forEach(([input, target, text]) => setError(input, target, text));
    const firstInvalid = checks.find(c => c[2]);
    if (firstInvalid) { firstInvalid[0].focus(); return; }

    button.disabled = true;
    button.textContent = 'Creating account...';

    const result = await SF.registerUser({ email: email.value, password: password.value });
    if (!result.ok) {
      message.textContent = result.error;
      button.disabled = false;
      button.textContent = 'Create new account';
      return;
    }

    await sendWelcomeEmail(result.user.email);
    location.replace('index.html?registered=1');
  });
}

/* =====================================================================
   home.html — dashboard & analytics

   Workout shape saved via SF.saveData({ programs, workouts }):
     workouts: [{
       id, date: 'YYYY-MM-DD', finishedAt: ISOString,
       programId, programName,               // optional, set when started from a program
       exercises: [{ name, sets: [{ reps, weight }] }]
     }]
   Every number on this page is derived from that array — nothing is
   stored pre-computed, so it is always in sync with whatever
   workouts.html writes to SF.saveData().
   ===================================================================== */

/* ---------- exercise -> muscle group classification ---------- */
const MUSCLE_GROUPS = ['Chest', 'Back', 'Shoulders', 'Arms', 'Legs', 'Core', 'Abdomen'];
const MUSCLE_MAP = [
  { muscle: 'Chest',     keys: ['bench press', 'chest press', 'incline press', 'decline press', 'push up', 'push-up', 'pushup', 'fly', 'flye', 'pec deck', 'dip'] },
  { muscle: 'Back',      keys: ['pull up', 'pull-up', 'pullup', 'lat pulldown', 'pulldown', 'row', 'deadlift'] },
  { muscle: 'Shoulders', keys: ['overhead press', 'shoulder press', 'military press', 'lateral raise', 'front raise', 'arnold press', 'shrug', 'upright row'] },
  { muscle: 'Arms',      keys: ['curl', 'tricep', 'triceps', 'pushdown', 'skull crusher', 'kickback'] },
  { muscle: 'Legs',      keys: ['squat', 'lunge', 'leg press', 'leg extension', 'leg curl', 'calf raise', 'hip thrust', 'romanian deadlift', 'rdl', 'glute bridge'] },
  { muscle: 'Core',      keys: ['plank', 'russian twist', 'wood chop', 'mountain climber'] },
  { muscle: 'Abdomen',   keys: ['crunch', 'sit up', 'sit-up', 'situp', 'ab wheel', 'leg raise'] }
];
function classifyMuscle(exerciseName) {
  const n = String(exerciseName || '').toLowerCase();
  const hit = MUSCLE_MAP.find(g => g.keys.some(k => n.includes(k)));
  return hit ? hit.muscle : null;
}

/* ---------- small date helpers (dates are kept as local, no timezone math) ---------- */
const pad2 = (n) => String(n).padStart(2, '0');
const toISODate = (d) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
const parseISODate = (s) => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
const addDays = (d, n) => { const r = new Date(d); r.setDate(r.getDate() + n); return r; };
const addMonths = (d, n) => { const r = new Date(d); r.setMonth(r.getMonth() + n); return r; };
const startOfMonth = (d) => new Date(d.getFullYear(), d.getMonth(), 1);
const endOfMonth = (d) => new Date(d.getFullYear(), d.getMonth() + 1, 0);
const startOfWeekMon = (d) => { const r = new Date(d); const day = (r.getDay() + 6) % 7; r.setDate(r.getDate() - day); return r; };
const fmtShort = (d) => `${pad2(d.getMonth() + 1)}/${pad2(d.getDate())}`;
const fmtMonthYear = (d) => d.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
const isoWeekKey = (d) => { const s = startOfWeekMon(d); return toISODate(s); };

/* ---------- flatten workouts into individual logged sets ---------- */
function flattenSets(workouts) {
  const out = [];
  for (const w of workouts) {
    for (const ex of (w.exercises || [])) {
      const muscle = classifyMuscle(ex.name);
      for (const s of (ex.sets || [])) {
        out.push({ date: w.date, exercise: ex.name, muscle, reps: Number(s.reps) || 0, weight: Number(s.weight) || 0 });
      }
    }
  }
  return out;
}

function statsForRange(workouts, sets, start, end) {
  const inRange = (dateStr) => { const d = parseISODate(dateStr); return d >= start && d <= end; };
  const workoutCount = workouts.filter(w => inRange(w.date)).length;
  const rangeSets = sets.filter(s => inRange(s.date));
  const volume = rangeSets.reduce((sum, s) => sum + s.reps * s.weight, 0);
  const totalSets = rangeSets.length;
  const totalReps = rangeSets.reduce((sum, s) => sum + s.reps, 0);
  return { workoutCount, volume, totalSets, totalReps };
}

function pctChange(current, previous) {
  if (previous === 0) return current === 0 ? null : 100;
  return Math.round(((current - previous) / previous) * 100);
}

function computeRecords(sets) {
  const best = new Map(); // exercise (lowercased) -> {exercise, weight, reps, date}
  for (const s of sets) {
    if (s.weight <= 0) continue;
    const key = s.exercise.trim().toLowerCase();
    const prev = best.get(key);
    if (!prev || s.weight > prev.weight) best.set(key, { exercise: s.exercise, weight: s.weight, reps: s.reps, date: s.date });
  }
  return Array.from(best.values()).sort((a, b) => b.weight - a.weight);
}

function computeFavourite(sets) {
  const counts = new Map();
  for (const s of sets) {
    const key = s.exercise.trim();
    if (!key) continue;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  let best = null;
  for (const [name, count] of counts) if (!best || count > best.count) best = { name, count };
  return best;
}

function computeMuscleStats(sets, days) {
  const since = addDays(new Date(), -(days - 1));
  since.setHours(0, 0, 0, 0);
  const counts = {};
  MUSCLE_GROUPS.forEach(m => (counts[m] = 0));
  let total = 0;
  for (const s of sets) {
    if (!s.muscle) continue;
    const d = parseISODate(s.date);
    if (d < since) continue;
    counts[s.muscle] += 1;
    total += 1;
  }
  return { counts, total };
}

function computeStreaks(workouts) {
  const weekKeys = Array.from(new Set(workouts.map(w => isoWeekKey(parseISODate(w.date))))).sort();
  if (weekKeys.length === 0) return { current: 0, longest: 0 };
  const weekIndex = (key) => Math.round((parseISODate(key) - parseISODate(weekKeys[0])) / (7 * 86400000));
  let longest = 1, run = 1;
  for (let i = 1; i < weekKeys.length; i++) {
    run = (weekIndex(weekKeys[i]) === weekIndex(weekKeys[i - 1]) + 1) ? run + 1 : 1;
    longest = Math.max(longest, run);
  }
  const lastWeek = weekKeys[weekKeys.length - 1];
  const thisWeek = isoWeekKey(new Date());
  const lastWeekPrev = isoWeekKey(addDays(new Date(), -7));
  let current = 0;
  if (lastWeek === thisWeek || lastWeek === lastWeekPrev) {
    current = 1;
    for (let i = weekKeys.length - 1; i > 0; i--) {
      if (weekIndex(weekKeys[i]) === weekIndex(weekKeys[i - 1]) + 1) current++; else break;
    }
  }
  return { current, longest };
}

function trainingDaysLastYear(workouts) {
  const since = addDays(new Date(), -365);
  return new Set(workouts.filter(w => parseISODate(w.date) >= since).map(w => w.date)).size;
}

function buildHeatmap(workouts) {
  const countByDate = new Map();
  for (const w of workouts) countByDate.set(w.date, (countByDate.get(w.date) || 0) + 1);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const start = startOfWeekMon(addDays(today, -7 * 51)); // 52 weeks back, week-aligned
  const weeks = [];
  let cursor = new Date(start);
  for (let w = 0; w < 53; w++) {
    const days = [];
    for (let d = 0; d < 7; d++) {
      const iso = toISODate(cursor);
      const count = cursor > today ? -1 : (countByDate.get(iso) || 0); // -1 = future, not rendered
      let level = 0;
      if (count === 1) level = 1; else if (count === 2) level = 2; else if (count >= 3 && count < 5) level = 3; else if (count >= 5) level = 4;
      days.push({ date: iso, count, level });
      cursor = addDays(cursor, 1);
    }
    weeks.push(days);
  }
  return weeks;
}

/* ---------- mobile sidebar drawer ---------- */
function initMobileNav() {
  const toggle = document.getElementById('mobile-nav-toggle');
  const sidebar = document.querySelector('.sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  if (!toggle || !sidebar) return;
  function close() {
    sidebar.classList.remove('is-open');
    if (backdrop) backdrop.classList.remove('is-visible');
  }
  toggle.addEventListener('click', () => {
    const open = sidebar.classList.toggle('is-open');
    if (backdrop) backdrop.classList.toggle('is-visible', open);
  });
  if (backdrop) backdrop.addEventListener('click', close);
  sidebar.querySelectorAll('a').forEach(a => a.addEventListener('click', close));
}

/* ---------- shared topbar (used by home.html, workouts.html, ...) ---------- */
function initTopbar(workoutCount) {
  const nameEl = document.getElementById('user-name');
  if (!nameEl) return;
  const user = SF.currentUser();
  const displayName = (user.name && user.name.trim()) || user.email.split('@')[0];
  const initials = displayName.trim().split(/\s+/).slice(0, 2).map(p => p[0].toUpperCase()).join('') || 'U';
  nameEl.textContent = displayName;
  document.getElementById('avatar-initials').textContent = initials;
  document.getElementById('user-level').textContent = 'Level ' + Math.floor(workoutCount / 5);
  document.getElementById('logout-btn').addEventListener('click', SF.logout);
  initMobileNav();
}

/* ---------- shared "workouts list" renderer (home.html + workouts.html) ---------- */
function renderWorkoutsListInto(containerId, list) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (list.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state__icon">🏋️</div>
        <p class="empty-state__title">No workouts yet</p>
        <p class="empty-state__sub">Start a workout to see it appear here!</p>
      </div>`;
    return;
  }
  const escape = (str) => String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const sorted = [...list].sort((a, b) => (b.finishedAt || b.date).localeCompare(a.finishedAt || a.date)).slice(0, 6);
  container.innerHTML = sorted.map(w => {
    const vol = flattenSets([w]).reduce((sum, s) => sum + s.reps * s.weight, 0);
    return `
      <div class="workout-row">
        <div>
          <div class="workout-row__name">${escape(w.programName || 'Workout')}</div>
          <div class="workout-row__meta">${w.date} · ${(w.exercises || []).length} exercises</div>
        </div>
        <div class="workout-row__volume">${vol >= 1000 ? (vol / 1000).toFixed(1) + 'k' : vol} kg</div>
      </div>`;
  }).join('');
}

/* ---------- dashboard controller ---------- */
function initHome() {
  const root = document.getElementById('dashboard-root');
  if (!root) return;

  const user = SF.currentUser();
  const data = SF.loadData();
  const workouts = data.workouts;
  const sets = flattenSets(workouts);

  /* ---- topbar ---- */
  initTopbar(workouts.length);

  /* ---- state ---- */
  let periodType = 'week';   // 'week' | 'month' | 'all'
  let metric = 'volume';     // 'volume' | 'sets' | 'reps'
  let anchor = new Date();   // reference date the current range is built from

  const metricLabel = { volume: 'Volume', sets: 'Sets', reps: 'Reps' };
  const metricUnit = { volume: 'kg', sets: '', reps: '' };

  function currentRange() {
    if (periodType === 'week') {
      const end = new Date(anchor); end.setHours(0, 0, 0, 0);
      return { start: addDays(end, -6), end };
    }
    if (periodType === 'month') {
      return { start: startOfMonth(anchor), end: endOfMonth(anchor) };
    }
    const firstDate = workouts.length ? workouts.map(w => parseISODate(w.date)).reduce((a, b) => a < b ? a : b) : new Date();
    return { start: firstDate, end: new Date() };
  }

  function previousRange(range) {
    const spanDays = Math.round((range.end - range.start) / 86400000) + 1;
    return { start: addDays(range.start, -spanDays), end: addDays(range.start, -1) };
  }

  function rangeLabel(range) {
    if (periodType === 'month') return fmtMonthYear(anchor);
    if (periodType === 'all') return 'All time';
    return `${fmtShort(range.start)} - ${fmtShort(range.end)}`;
  }

  function buildSeries(range) {
    const buckets = [];
    if (periodType === 'all') {
      let cur = startOfMonth(range.start);
      const last = startOfMonth(range.end);
      while (cur <= last) {
        buckets.push({ label: cur.toLocaleDateString('en-US', { month: 'short' }), start: new Date(cur), end: endOfMonth(cur) });
        cur = addMonths(cur, 1);
      }
    } else {
      let cur = new Date(range.start);
      while (cur <= range.end) {
        buckets.push({ label: fmtShort(cur), start: new Date(cur), end: new Date(cur) });
        cur = addDays(cur, 1);
      }
    }
    const values = buckets.map(b => {
      const bucketSets = sets.filter(s => { const d = parseISODate(s.date); return d >= b.start && d <= b.end; });
      if (metric === 'volume') return bucketSets.reduce((sum, s) => sum + s.reps * s.weight, 0);
      if (metric === 'sets') return bucketSets.length;
      return bucketSets.reduce((sum, s) => sum + s.reps, 0);
    });
    return { labels: buckets.map(b => b.label), values };
  }

  /* ---- chart ---- */
  const ctx = document.getElementById('progress-chart').getContext('2d');
  const cyan = getComputedStyle(document.documentElement).getPropertyValue('--cyan').trim() || '#00f0ff';
  const chart = new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [{ data: [], borderColor: cyan, backgroundColor: cyan + '22', borderWidth: 3, fill: true, tension: 0.35, pointRadius: 0 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { intersect: false, mode: 'index' } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,.06)' }, ticks: { color: '#8b93a7', maxRotation: 0, autoSkip: true } },
        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,.06)' }, ticks: { color: '#8b93a7' } }
      }
    }
  });

  /* ---- stat card helper ---- */
  function setStat(idPrefix, current, previous, formatter) {
    document.getElementById('stat-' + idPrefix).textContent = formatter(current);
    const sub = document.getElementById('stat-' + idPrefix + '-sub');
    const change = pctChange(current, previous);
    if (change === null) sub.textContent = 'No data in previous period';
    else if (change === 0) sub.textContent = 'No change from last period';
    else sub.textContent = `${change > 0 ? '▲' : '▼'} ${Math.abs(change)}% vs last period`;
  }

  /* ---- render ---- */
  function render() {
    const range = currentRange();
    const prevRange = previousRange(range);

    document.getElementById('range-label').textContent = rangeLabel(range);
    const disableNav = periodType === 'all';
    document.getElementById('range-prev').disabled = disableNav;
    document.getElementById('range-next').disabled = disableNav || (periodType !== 'all' && addDays(range.end, 1) > new Date() && periodType === 'week') && false;

    const cur = statsForRange(workouts, sets, range.start, range.end);
    const prev = statsForRange(workouts, sets, prevRange.start, prevRange.end);
    setStat('workouts', cur.workoutCount, prev.workoutCount, (v) => String(v));
    setStat('volume', cur.volume, prev.volume, (v) => (v >= 1000 ? (v / 1000).toFixed(1) + 'k' : Math.round(v).toString()));
    setStat('sets', cur.totalSets, prev.totalSets, (v) => String(v));
    setStat('reps', cur.totalReps, prev.totalReps, (v) => String(v));

    const series = buildSeries(range);
    chart.data.labels = series.labels;
    chart.data.datasets[0].data = series.values;
    chart.options.scales.y.ticks.callback = (v) => metric === 'volume' && v >= 1000 ? (v / 1000) + 'k' : v;
    chart.update();

    /* records */
    const records = computeRecords(sets);
    const recordsList = document.getElementById('records-list');
    recordsList.innerHTML = '';
    if (records.length === 0) {
      recordsList.innerHTML = '<li class="records-empty">No records yet — log a workout to set your first.</li>';
    } else {
      records.slice(0, 6).forEach(r => {
        const li = document.createElement('li');
        li.className = 'records-item';
        li.innerHTML = `<span class="records-item__name">${escapeHtml(r.exercise)}</span><span class="records-item__value">${r.weight} kg × ${r.reps}</span>`;
        recordsList.appendChild(li);
      });
    }

    /* favourite exercise */
    const fav = computeFavourite(sets);
    document.getElementById('favourite-exercise').textContent = fav ? fav.name : 'No favourite yet';
    document.getElementById('favourite-exercise').classList.toggle('is-empty', !fav);

    /* sets per week + muscle distribution (fixed trailing 7-day window) */
    const muscleStats = computeMuscleStats(sets, 7);
    const setsPerWeekEl = document.getElementById('sets-per-week');
    const withCounts = MUSCLE_GROUPS.filter(m => muscleStats.counts[m] > 0);
    if (withCounts.length === 0) {
      setsPerWeekEl.innerHTML = '<p class="empty-note">No sets in this period.</p>';
    } else {
      const max = Math.max(...withCounts.map(m => muscleStats.counts[m]));
      setsPerWeekEl.innerHTML = withCounts
        .sort((a, b) => muscleStats.counts[b] - muscleStats.counts[a])
        .map(m => `
          <div class="muscle-bar-row">
            <span class="muscle-bar-row__label">${m}</span>
            <div class="muscle-bar-row__track"><div class="muscle-bar-row__fill" style="width:${(muscleStats.counts[m] / max * 100).toFixed(0)}%"></div></div>
            <span class="muscle-bar-row__value">${muscleStats.counts[m]}</span>
          </div>`).join('');
    }
    MUSCLE_GROUPS.forEach(m => {
      const pct = muscleStats.total ? Math.round(muscleStats.counts[m] / muscleStats.total * 100) : 0;
      const badge = document.querySelector(`.muscle-badge[data-muscle="${m}"] .muscle-badge__pct`);
      if (badge) badge.textContent = pct + '%';
    });

    /* activity: streak + heatmap */
    const streaks = computeStreaks(workouts);
    document.getElementById('current-streak').textContent = streaks.current + ' wks';
    document.getElementById('longest-streak').textContent = streaks.longest + ' wks';
    document.getElementById('training-days').textContent = trainingDaysLastYear(workouts);
    renderHeatmap(buildHeatmap(workouts));

    /* recent workouts */
    renderWorkoutsList(workouts);
  }

  function renderHeatmap(weeks) {
    const grid = document.getElementById('activity-grid');
    grid.innerHTML = '';
    grid.style.gridTemplateColumns = `repeat(${weeks.length}, 1fr)`;
    weeks.forEach(week => {
      const col = document.createElement('div');
      col.className = 'heatmap-col';
      week.forEach(day => {
        const cell = document.createElement('div');
        cell.className = 'heatmap-cell' + (day.count < 0 ? ' heatmap-cell--future' : ` heatmap-cell--l${day.level}`);
        cell.title = day.count >= 0 ? `${day.date}: ${day.count} workout(s)` : '';
        col.appendChild(cell);
      });
      grid.appendChild(col);
    });
  }

  function renderWorkoutsList(list) {
    renderWorkoutsListInto('workouts-list', list);
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  /* ---- controls ---- */
  document.getElementById('metric-select').addEventListener('change', (e) => { metric = e.target.value; render(); });
  document.getElementById('period-select').addEventListener('change', (e) => { periodType = e.target.value; anchor = new Date(); render(); });
  document.getElementById('range-prev').addEventListener('click', () => {
    anchor = periodType === 'month' ? addMonths(anchor, -1) : addDays(anchor, -7);
    render();
  });
  document.getElementById('range-next').addEventListener('click', () => {
    anchor = periodType === 'month' ? addMonths(anchor, 1) : addDays(anchor, 7);
    render();
  });
  document.getElementById('start-empty-workout').addEventListener('click', () => { location.href = 'workouts.html?start=empty'; });

  render();
}

/* =====================================================================
   workouts.html — plans wizard + live workout session
   ===================================================================== */
function uid(prefix) { return prefix + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

function initWorkouts() {
  const root = document.getElementById('workouts-root');
  if (!root) return;

  const data = SF.loadData();
  initTopbar(data.workouts.length);
  const views = {
    landing: document.getElementById('view-landing'),
    wizard: document.getElementById('view-wizard'),
    session: document.getElementById('view-session')
  };
  function showView(name) {
    Object.entries(views).forEach(([key, el]) => { el.style.display = key === name ? '' : 'none'; });
  }

  /* ================= LANDING ================= */
  function renderPlans() {
    const list = document.getElementById('plans-list');
    if (data.programs.length === 0) {
      list.innerHTML = `
        <div class="empty-state span-all">
          <div class="empty-state__icon">🏋️</div>
          <p class="empty-state__title">No workout plans yet</p>
          <p class="empty-state__sub">Create your first workout plan to get started on your fitness journey.</p>
        </div>`;
      list.classList.add('empty-wrap');
      return;
    }
    list.classList.remove('empty-wrap');
    list.innerHTML = data.programs.map(p => `
      <div class="plan-card">
        <h4>${escapeHtml(p.title)}</h4>
        <p>${escapeHtml(p.description || 'No description.')}</p>
        <div class="plan-card__tags">
          ${p.difficulty ? `<span class="tag">${escapeHtml(p.difficulty)}</span>` : ''}
          ${p.equipment ? `<span class="tag">${escapeHtml(p.equipment)}</span>` : ''}
          <span class="tag">${p.templates.length} day${p.templates.length === 1 ? '' : 's'}</span>
        </div>
        <div class="plan-card__actions">
          <button type="button" class="btn btn--primary btn--small" data-start-plan="${p.id}">Start</button>
          <button type="button" class="btn btn--alt btn--small" data-delete-plan="${p.id}">Delete</button>
        </div>
      </div>`).join('');

    list.querySelectorAll('[data-start-plan]').forEach(btn => {
      btn.addEventListener('click', () => startSessionFromPlan(btn.dataset.startPlan));
    });
    list.querySelectorAll('[data-delete-plan]').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!confirm('Delete this workout plan?')) return;
        data.programs = data.programs.filter(p => p.id !== btn.dataset.deletePlan);
        SF.saveData(data);
        renderPlans();
      });
    });
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function renderHistory() {
    renderWorkoutsListInto('workouts-history-list', data.workouts);
  }

  document.getElementById('start-empty-workout-btn').addEventListener('click', () => startSession(null));
  document.getElementById('create-plan-btn').addEventListener('click', () => { resetWizard(); showView('wizard'); });
  document.getElementById('explore-plans-btn').addEventListener('click', () => {
    document.getElementById('plans-section').scrollIntoView({ behavior: 'smooth' });
  });

  /* ================= WIZARD (3 steps) ================= */
  let wizardStep = 1;
  let templates = [];

  function resetWizard() {
    wizardStep = 1;
    templates = [{ id: uid('tpl'), day: 'Monday', exercises: [] }];
    document.getElementById('wizard-title').value = '';
    document.getElementById('wizard-description').value = '';
    document.getElementById('wizard-difficulty').value = '';
    document.getElementById('wizard-equipment').value = '';
    renderWizardStep();
  }

  function renderWizardStep() {
    document.querySelectorAll('.wizard-panel').forEach(p => p.style.display = 'none');
    document.getElementById('wizard-panel-' + wizardStep).style.display = '';
    document.getElementById('wizard-step-name').textContent =
      wizardStep === 1 ? 'Program Details' : wizardStep === 2 ? 'Workout Templates' : 'Review & Create';
    document.getElementById('wizard-step-count').textContent = wizardStep + ' of 3';
    document.getElementById('wizard-progress-fill').style.width = (wizardStep / 3 * 100) + '%';
    document.getElementById('wizard-prev').style.visibility = wizardStep === 1 ? 'hidden' : 'visible';
    document.getElementById('wizard-next').textContent = wizardStep === 3 ? 'Create Program' : 'Next';
    document.getElementById('wizard-next').querySelector('.arrow').textContent = wizardStep === 3 ? '✓' : '→';
    if (wizardStep === 2) renderTemplates();
    if (wizardStep === 3) renderReview();
  }

  function renderTemplates() {
    const container = document.getElementById('templates-container');
    container.innerHTML = templates.map((tpl, i) => `
      <div class="template-card" data-tpl="${tpl.id}">
        <div class="template-card__head">
          <div>
            <h4>Workout ${i + 1}</h4>
            <select class="select tpl-day" data-tpl="${tpl.id}">
              ${['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'].map(d => `<option ${d === tpl.day ? 'selected' : ''}>${d}</option>`).join('')}
            </select>
          </div>
          <div style="display:flex; gap:10px; align-items:center;">
            <button type="button" class="btn btn--alt btn--small add-exercise-btn" data-tpl="${tpl.id}">+ Add Exercise</button>
            ${templates.length > 1 ? `<button type="button" class="template-card__remove" data-remove-tpl="${tpl.id}" title="Remove template">✕</button>` : ''}
          </div>
        </div>
        <div class="tpl-exercises" data-tpl="${tpl.id}">
          ${tpl.exercises.map(ex => exerciseRowHtml(tpl.id, ex)).join('')}
        </div>
        <p class="exercise-count">${tpl.exercises.length} exercise(s) configured</p>
      </div>`).join('');

    container.querySelectorAll('.tpl-day').forEach(sel => sel.addEventListener('change', (e) => {
      templates.find(t => t.id === e.target.dataset.tpl).day = e.target.value;
    }));
    container.querySelectorAll('.add-exercise-btn').forEach(btn => btn.addEventListener('click', () => {
      const tpl = templates.find(t => t.id === btn.dataset.tpl);
      tpl.exercises.push({ id: uid('ex'), name: '', sets: 3, reps: 10, weight: '' });
      renderTemplates();
    }));
    wireExerciseRows(container);
  }

  function exerciseRowHtml(tplId, ex) {
    return `
      <div class="exercise-row" data-ex="${ex.id}" data-tpl="${tplId}">
        <input type="text" class="input ex-name" placeholder="Exercise name" value="${ex.name.replace(/"/g, '&quot;')}">
        <input type="number" min="1" class="input ex-sets" placeholder="Sets" value="${ex.sets}">
        <input type="number" min="1" class="input ex-reps" placeholder="Reps" value="${ex.reps}">
        <input type="number" min="0" step="0.5" class="input ex-weight" placeholder="Weight (kg)" value="${ex.weight}">
        <button type="button" class="exercise-row__remove" title="Remove">✕</button>
      </div>`;
  }

  function wireExerciseRows(container) {
    container.querySelectorAll('.exercise-row').forEach(row => {
      const tpl = templates.find(t => t.id === row.dataset.tpl);
      const ex = tpl.exercises.find(e => e.id === row.dataset.ex);
      row.querySelector('.ex-name').addEventListener('input', (e) => { ex.name = e.target.value; });
      row.querySelector('.ex-sets').addEventListener('input', (e) => { ex.sets = Number(e.target.value) || 1; });
      row.querySelector('.ex-reps').addEventListener('input', (e) => { ex.reps = Number(e.target.value) || 1; });
      row.querySelector('.ex-weight').addEventListener('input', (e) => { ex.weight = e.target.value; });
      row.querySelector('.exercise-row__remove').addEventListener('click', () => {
        tpl.exercises = tpl.exercises.filter(e => e.id !== ex.id);
        renderTemplates();
      });
    });
    container.querySelectorAll('[data-remove-tpl]').forEach(btn => btn.addEventListener('click', () => {
      templates = templates.filter(t => t.id !== btn.dataset.removeTpl);
      renderTemplates();
    }));
  }

  document.getElementById('add-template-btn').addEventListener('click', () => {
    templates.push({ id: uid('tpl'), day: 'Monday', exercises: [] });
    renderTemplates();
  });

  function renderReview() {
    const title = document.getElementById('wizard-title').value.trim() || 'Untitled program';
    const description = document.getElementById('wizard-description').value.trim();
    const difficulty = document.getElementById('wizard-difficulty').value;
    const equipment = document.getElementById('wizard-equipment').value;
    document.getElementById('review-content').innerHTML = `
      <div class="review-block">
        <h4>${escapeHtml(title)}</h4>
        <p>${escapeHtml(description || 'No description.')}</p>
        <div class="review-badges">
          ${difficulty ? `<span class="tag">${escapeHtml(difficulty)}</span>` : ''}
          ${equipment ? `<span class="tag">${escapeHtml(equipment)}</span>` : ''}
        </div>
      </div>
      ${templates.map((t, i) => `
        <div class="review-block">
          <h4>Workout ${i + 1} · ${escapeHtml(t.day)}</h4>
          <p>${t.exercises.length ? t.exercises.map(e => escapeHtml(e.name || 'Unnamed exercise') + ` (${e.sets}×${e.reps}${e.weight ? ', ' + e.weight + ' kg' : ''})`).join(', ') : 'No exercises added.'}</p>
        </div>`).join('')}
    `;
  }

  document.getElementById('wizard-prev').addEventListener('click', () => { if (wizardStep > 1) { wizardStep--; renderWizardStep(); } });
  document.getElementById('wizard-cancel').addEventListener('click', () => showView('landing'));
  document.getElementById('wizard-next').addEventListener('click', () => {
    if (wizardStep === 1) {
      const title = document.getElementById('wizard-title').value.trim();
      if (!title) { document.getElementById('wizard-title').focus(); document.getElementById('wizard-title').setAttribute('aria-invalid', 'true'); return; }
      document.getElementById('wizard-title').setAttribute('aria-invalid', 'false');
    }
    if (wizardStep < 3) { wizardStep++; renderWizardStep(); return; }

    // final step -> save program
    const program = {
      id: uid('prog'),
      title: document.getElementById('wizard-title').value.trim() || 'Untitled program',
      description: document.getElementById('wizard-description').value.trim(),
      difficulty: document.getElementById('wizard-difficulty').value,
      equipment: document.getElementById('wizard-equipment').value,
      templates: templates.map(t => ({ id: t.id, day: t.day, exercises: t.exercises.filter(e => e.name.trim()) }))
    };
    data.programs.push(program);
    SF.saveData(data);
    renderPlans();
    showView('landing');
  });

  /* ================= LIVE SESSION ================= */
  let sessionExercises = [];
  let sessionProgram = null;
  let sessionTemplate = null;

  function startSession(program, template) {
    sessionProgram = program;
    sessionTemplate = template || null;
    sessionExercises = template
      ? template.exercises.map(e => ({ id: uid('sx'), name: e.name, sets: Array.from({ length: e.sets }, () => ({ reps: e.reps, weight: e.weight || '' })) }))
      : [];
    document.getElementById('session-title').textContent = program ? program.title : 'Empty Workout';
    renderSession();
    showView('session');
  }

  function startSessionFromPlan(programId) {
    const program = data.programs.find(p => p.id === programId);
    if (!program) return;
    const template = program.templates[0] || null;
    startSession(program, template);
  }

  function renderSession() {
    const container = document.getElementById('session-exercises');
    if (sessionExercises.length === 0) {
      container.innerHTML = '<p class="empty-note">No exercises yet — click "Add Exercise" to start logging.</p>';
    } else {
      container.innerHTML = sessionExercises.map(ex => `
        <div class="session-exercise" data-ex="${ex.id}">
          <div class="session-exercise__head">
            <input type="text" class="input sx-name" placeholder="Exercise name" value="${ex.name.replace(/"/g, '&quot;')}">
            <button type="button" class="exercise-row__remove sx-remove" title="Remove exercise">✕</button>
          </div>
          ${ex.sets.map((s, i) => `
            <div class="session-set-row" data-set-index="${i}">
              <span class="session-set-row__index">${i + 1}</span>
              <input type="number" min="0" class="input sx-reps" placeholder="Reps" value="${s.reps}">
              <input type="number" min="0" step="0.5" class="input sx-weight" placeholder="Weight (kg)" value="${s.weight}">
              <button type="button" class="exercise-row__remove sx-remove-set" title="Remove set">✕</button>
            </div>`).join('')}
          <button type="button" class="add-set-btn sx-add-set">+ Add set</button>
        </div>`).join('');
    }
    wireSessionRows(container);
  }

  function wireSessionRows(container) {
    container.querySelectorAll('.session-exercise').forEach(card => {
      const ex = sessionExercises.find(e => e.id === card.dataset.ex);
      card.querySelector('.sx-name').addEventListener('input', (e) => { ex.name = e.target.value; });
      card.querySelector('.sx-remove').addEventListener('click', () => {
        sessionExercises = sessionExercises.filter(e => e.id !== ex.id);
        renderSession();
      });
      card.querySelectorAll('.session-set-row').forEach(row => {
        const idx = Number(row.dataset.setIndex);
        row.querySelector('.sx-reps').addEventListener('input', (e) => { ex.sets[idx].reps = Number(e.target.value) || 0; });
        row.querySelector('.sx-weight').addEventListener('input', (e) => { ex.sets[idx].weight = e.target.value; });
        row.querySelector('.sx-remove-set').addEventListener('click', () => {
          ex.sets.splice(idx, 1);
          renderSession();
        });
      });
      card.querySelector('.sx-add-set').addEventListener('click', () => {
        const last = ex.sets[ex.sets.length - 1];
        ex.sets.push({ reps: last ? last.reps : 10, weight: last ? last.weight : '' });
        renderSession();
      });
    });
  }

  document.getElementById('session-add-exercise').addEventListener('click', () => {
    sessionExercises.push({ id: uid('sx'), name: '', sets: [{ reps: 10, weight: '' }] });
    renderSession();
  });

  document.getElementById('session-cancel').addEventListener('click', () => {
    if (confirm('Discard this workout?')) showView('landing');
  });

  document.getElementById('session-finish').addEventListener('click', () => {
    const cleanExercises = sessionExercises
      .map(ex => ({
        name: ex.name.trim(),
        sets: ex.sets
          .map(s => ({ reps: Number(s.reps) || 0, weight: Number(s.weight) || 0 }))
          .filter(s => s.reps > 0)
      }))
      .filter(ex => ex.name && ex.sets.length > 0);

    if (cleanExercises.length === 0) {
      alert('Add at least one exercise with a logged set before finishing.');
      return;
    }

    const now = new Date();
    data.workouts.push({
      id: uid('wk'),
      date: toISODate(now),
      finishedAt: now.toISOString(),
      programId: sessionProgram ? sessionProgram.id : null,
      programName: sessionProgram ? sessionProgram.title : null,
      exercises: cleanExercises
    });
    SF.saveData(data);
    location.href = 'home.html';
  });

  /* ---------- boot ---------- */
  renderPlans();
  renderHistory();
  if (new URLSearchParams(location.search).get('start') === 'empty') {
    startSession(null);
  } else {
    showView('landing');
  }
}

/* =====================================================================
   calendar.html — training calendar + monthly goal
   goal shape: { targetType: 'month'|'week', target: number, days: ['Su',...],
                 timeEnabled: bool, time: 'HH:MM' }
   ===================================================================== */
const WEEKDAY_CODES = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];

function initCalendar() {
  const root = document.getElementById('calendar-root');
  if (!root) return;

  const data = SF.loadData();
  initTopbar(data.workouts.length);

  const today = new Date(); today.setHours(0, 0, 0, 0);
  let viewMonth = new Date(today.getFullYear(), today.getMonth(), 1);
  let selectedDate = new Date(today);

  const workoutDatesSet = () => new Set(data.workouts.map(w => w.date));

  function isTrainingDay(date) {
    if (!data.goal || !data.goal.days || !data.goal.days.length) return false;
    return data.goal.days.includes(WEEKDAY_CODES[date.getDay()]);
  }

  function dayStatus(date) {
    const iso = toISODate(date);
    if (workoutDatesSet().has(iso)) return 'completed';
    if (isTrainingDay(date)) return date < today ? 'missed' : 'planned';
    return 'none';
  }

  /* ---------- goal summary card ---------- */
  function renderGoalCard() {
    const emptyEl = document.getElementById('goal-summary-empty');
    const setEl = document.getElementById('goal-summary-set');
    const monthWorkouts = data.workouts.filter(w => {
      const d = parseISODate(w.date);
      return d.getFullYear() === viewMonth.getFullYear() && d.getMonth() === viewMonth.getMonth();
    }).length;

    if (!data.goal) {
      emptyEl.style.display = '';
      setEl.style.display = 'none';
      document.getElementById('goal-month-count').textContent = monthWorkouts;
      return;
    }
    emptyEl.style.display = 'none';
    setEl.style.display = 'flex';
    const target = data.goal.targetType === 'week' ? Math.round(data.goal.target * 4.345) : data.goal.target;
    document.getElementById('goal-ring-value').textContent = `${monthWorkouts}/${target}`;
    document.getElementById('goal-ring-monthname').textContent = viewMonth.toLocaleDateString('en-US', { month: 'long' }).toUpperCase();
  }

  document.getElementById('open-goal-modal-empty').addEventListener('click', openGoalModal);
  document.getElementById('open-goal-modal-edit').addEventListener('click', openGoalModal);

  /* ---------- calendar grid ---------- */
  function renderCalendar() {
    document.getElementById('cal-month-label').textContent = viewMonth.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    const grid = document.getElementById('cal-grid');
    grid.innerHTML = '';

    const firstWeekday = viewMonth.getDay(); // 0 = Sunday
    const daysInMonth = endOfMonth(viewMonth).getDate();
    const prevMonthDays = startOfMonth(viewMonth).getDay();
    const prevMonth = addMonths(viewMonth, -1);
    const daysInPrevMonth = endOfMonth(prevMonth).getDate();

    const cells = [];
    for (let i = prevMonthDays - 1; i >= 0; i--) {
      cells.push({ date: new Date(prevMonth.getFullYear(), prevMonth.getMonth(), daysInPrevMonth - i), muted: true });
    }
    for (let d = 1; d <= daysInMonth; d++) cells.push({ date: new Date(viewMonth.getFullYear(), viewMonth.getMonth(), d), muted: false });
    while (cells.length % 7 !== 0) {
      const last = cells[cells.length - 1].date;
      cells.push({ date: addDays(last, 1), muted: true });
    }

    cells.forEach(cell => {
      const el = document.createElement('div');
      const status = cell.muted ? 'none' : dayStatus(cell.date);
      el.className = 'cal-day' + (cell.muted ? ' cal-day--muted' : '') +
        (status === 'planned' ? ' cal-day--planned' : '') +
        (status === 'missed' ? ' cal-day--missed' : '') +
        (toISODate(cell.date) === toISODate(selectedDate) ? ' cal-day--selected' : '');
      el.innerHTML = `<span>${cell.date.getDate()}</span>` + (status === 'completed' ? '<span class="cal-day__dot"></span>' : '');
      if (!cell.muted) el.addEventListener('click', () => { selectedDate = cell.date; renderCalendar(); renderSidePanel(); });
      grid.appendChild(el);
    });

    renderGoalCard();
  }

  document.getElementById('cal-prev-month').addEventListener('click', () => { viewMonth = addMonths(viewMonth, -1); renderCalendar(); });
  document.getElementById('cal-next-month').addEventListener('click', () => { viewMonth = addMonths(viewMonth, 1); renderCalendar(); });

  /* ---------- right-hand side panel ---------- */
  function renderSidePanel() {
    document.getElementById('cal-selected-date').textContent =
      selectedDate.toLocaleDateString('en-US', { day: 'numeric', month: 'long' }).toUpperCase();

    const iso = toISODate(selectedDate);
    const actionRow = document.getElementById('cal-action-row');
    const status = dayStatus(selectedDate);

    if (status === 'planned' || status === 'missed') {
      const timeStr = data.goal.timeEnabled && data.goal.time ? ' · ' + data.goal.time : '';
      actionRow.innerHTML = `<span>📅 ${status === 'missed' ? 'Missed workout' : 'Planned workout'}${timeStr}</span><span>›</span>`;
      actionRow.onclick = () => { location.href = 'workouts.html?start=empty'; };
    } else {
      actionRow.innerHTML = `<span>📅 Plan a workout</span><span>›</span>`;
      actionRow.onclick = openGoalModal;
    }

    const dayWorkouts = data.workouts.filter(w => w.date === iso);
    const box = document.getElementById('cal-day-workouts');
    if (dayWorkouts.length === 0) {
      box.innerHTML = `<div class="cal-day-workouts__icon">📅</div><div>No workouts for this day</div>`;
    } else {
      box.innerHTML = dayWorkouts.map(w => {
        const vol = flattenSets([w]).reduce((sum, s) => sum + s.reps * s.weight, 0);
        return `<div class="workout-row"><div><div class="workout-row__name">${w.programName || 'Workout'}</div><div class="workout-row__meta">${(w.exercises || []).length} exercises</div></div><div class="workout-row__volume">${vol} kg</div></div>`;
      }).join('');
    }
  }

  /* ---------- goal / schedule modal ---------- */
  const modal = document.getElementById('goal-modal');
  let selDays = [];
  let manualGoalEdit = false;

  function openGoalModal() {
    const g = data.goal;
    selDays = g ? [...g.days] : [];
    manualGoalEdit = false;
    document.getElementById('goal-number-input').value = g ? g.target : 12;
    setSegment(g ? g.targetType : 'month');
    document.getElementById('time-toggle').checked = g ? g.timeEnabled : false;
    document.getElementById('time-input').value = g && g.time ? g.time : '18:00';
    document.getElementById('time-input').style.display = (g && g.timeEnabled) ? '' : 'none';
    renderDayToggles();
    updatePreview();
    modal.style.display = 'flex';
  }
  function closeGoalModal() { modal.style.display = 'none'; }

  function setSegment(type) {
    document.querySelectorAll('.segmented button').forEach(b => b.classList.toggle('is-active', b.dataset.segment === type));
    document.getElementById('goal-unit-label').textContent = '/' + type;
  }
  document.querySelectorAll('.segmented button').forEach(btn => btn.addEventListener('click', () => {
    setSegment(btn.dataset.segment);
    if (!manualGoalEdit) autoFillGoal();
    updatePreview();
  }));

  function renderDayToggles() {
    const row = document.getElementById('day-toggle-row');
    row.innerHTML = WEEKDAY_CODES.map(code => `<button type="button" class="day-toggle${selDays.includes(code) ? ' is-active' : ''}" data-day="${code}">${code}</button>`).join('');
    row.querySelectorAll('.day-toggle').forEach(btn => btn.addEventListener('click', () => {
      const code = btn.dataset.day;
      selDays = selDays.includes(code) ? selDays.filter(d => d !== code) : [...selDays, code];
      renderDayToggles();
      if (!manualGoalEdit) autoFillGoal();
      updatePreview();
    }));
  }

  function currentSegment() { return document.querySelector('.segmented button.is-active').dataset.segment; }

  function autoFillGoal() {
    const perWeek = selDays.length;
    const value = currentSegment() === 'week' ? perWeek : Math.round(perWeek * 4.345);
    document.getElementById('goal-number-input').value = value || '';
  }

  document.getElementById('goal-number-input').addEventListener('input', () => { manualGoalEdit = true; updatePreview(); });
  document.getElementById('time-toggle').addEventListener('change', (e) => {
    document.getElementById('time-input').style.display = e.target.checked ? '' : 'none';
    updatePreview();
  });
  document.getElementById('time-input').addEventListener('input', updatePreview);

  function updatePreview() {
    const perWeek = selDays.length;
    document.getElementById('day-estimate').textContent =
      perWeek === 0 ? 'Pick at least one training day.' : `${perWeek} day${perWeek === 1 ? '' : 's'} a week · ≈${Math.round(perWeek * 4.345)} workouts/mo`;

    const target = Number(document.getElementById('goal-number-input').value) || 0;
    const monthlyTarget = currentSegment() === 'week' ? Math.round(target * 4.345) : target;
    const timeOn = document.getElementById('time-toggle').checked;
    const timeVal = document.getElementById('time-input').value;
    const dayList = selDays.length ? selDays.join(' / ') : '—';
    document.getElementById('schedule-preview-text').textContent =
      `Workouts this month: ${monthlyTarget} (${dayList}${timeOn ? ' at ' + timeVal : ''})`;
  }

  document.getElementById('goal-modal-close').addEventListener('click', closeGoalModal);
  document.getElementById('goal-modal').addEventListener('click', (e) => { if (e.target.id === 'goal-modal') closeGoalModal(); });

  document.getElementById('save-schedule-btn').addEventListener('click', () => {
    if (selDays.length === 0) { alert('Pick at least one training day.'); return; }
    data.goal = {
      targetType: currentSegment(),
      target: Number(document.getElementById('goal-number-input').value) || selDays.length,
      days: selDays,
      timeEnabled: document.getElementById('time-toggle').checked,
      time: document.getElementById('time-input').value
    };
    SF.saveData(data);
    closeGoalModal();
    renderCalendar();
    renderSidePanel();

    // count matching weekday dates for the rest of the calendar year, for the toast
    let plannedCount = 0;
    let cursor = new Date(today);
    const yearEnd = new Date(today.getFullYear(), 11, 31);
    while (cursor <= yearEnd) {
      if (isTrainingDay(cursor)) plannedCount++;
      cursor = addDays(cursor, 1);
    }
    showToast(`Schedule saved · ${plannedCount} days planned`);
  });

  let toastTimer = null;
  function showToast(text) {
    const toast = document.getElementById('cal-toast');
    toast.querySelector('span:last-child').textContent = text;
    toast.classList.add('is-visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 4000);
  }

  /* ---------- boot ---------- */
  renderCalendar();
  renderSidePanel();
}

/* =====================================================================
   exercise.html — exercise library
   ===================================================================== */
const MUSCLE_LIST = ['Chest', 'Triceps', 'Shoulders', 'Quadriceps', 'Glutes', 'Hamstrings', 'Back', 'Biceps', 'Calves', 'Core', 'Obliques', 'Hip Flexors', 'Lower Back', 'Forearms'];

const EXERCISE_LIBRARY = [
  {
    id: 'bench-press', name: 'Bench Press', muscles: ['Front Deltoid', 'Chest', 'Triceps', 'Biceps'],
    video: 'bench-press.mp4',
    description: 'Жим лежа — это классическое силовое упражнение, направленное на развитие мышц груди, плеч и трицепсов. Лягте на скамью, возьмитесь за гриф штанги чуть шире плеч, опустите его к груди, а затем мощно поднимитесь вверх. Это упражнение развивает мышечную массу и силу верхней части тела.'
  },
  { id: 'squat', name: 'Squat', muscles: ['Quadriceps', 'Glutes', 'Hamstrings', 'Calves'],
    description: 'A full-body compound lift. Stand with feet shoulder-width apart, bend your knees and hips to lower into a squat, keeping your chest up, then drive back up through your heels.' },
  { id: 'deadlift', name: 'Deadlift', muscles: ['Glutes', 'Hamstrings', 'Back', 'Forearms'],
    description: 'A hip-hinge movement that builds total-body strength. Grip the bar just outside your legs, keep your back flat, and stand up by driving your hips forward.' },
  { id: 'pull-up', name: 'Pull Up', muscles: ['Biceps', 'Back', 'Shoulders'],
    description: 'A bodyweight pulling exercise. Hang from a bar with palms facing away, then pull your chin above the bar by driving your elbows down and back.' },
  { id: 'bicep-curl', name: 'Bicep Curl', muscles: ['Biceps', 'Forearms'],
    description: 'An isolation move for the biceps. Hold a dumbbell in each hand, keep your elbows tucked in, and curl the weight up toward your shoulders.' },
  { id: 'tricep-dip', name: 'Tricep Dip', muscles: ['Chest', 'Triceps', 'Shoulders'],
    description: 'A pressing exercise for the triceps and chest. Lower your body by bending your elbows, then push back up until your arms are straight.' },
  { id: 'shoulder-press', name: 'Shoulder Press', muscles: ['Triceps', 'Shoulders', 'Chest'],
    description: 'An overhead pressing movement. Press the weights straight up above your shoulders until your arms are fully extended, then lower with control.' },
  { id: 'leg-press', name: 'Leg Press', muscles: ['Quadriceps', 'Glutes', 'Hamstrings'],
    description: 'A machine-based leg exercise. Push the platform away by extending your knees and hips, then return under control without locking your knees.' },
  { id: 'lunge', name: 'Lunge', muscles: ['Quadriceps', 'Glutes', 'Hamstrings', 'Calves'],
    description: 'A unilateral leg exercise. Step forward and lower your back knee toward the floor, keeping your front knee over your ankle, then push back to standing.' },
  { id: 'leg-curl', name: 'Leg Curl', muscles: ['Hamstrings', 'Glutes'],
    description: 'An isolation exercise for the hamstrings. Curl the pad toward your glutes by bending your knees, then lower back down slowly.' },
  { id: 'chest-fly', name: 'Chest Fly', muscles: ['Chest', 'Shoulders'],
    description: 'An isolation move for the chest. With a slight bend in your elbows, bring your arms together in front of you in a wide arc, then return slowly.' },
  { id: 'lat-pulldown', name: 'Lat Pulldown', muscles: ['Biceps', 'Back', 'Forearms'],
    description: 'A machine pulling exercise for the back. Pull the bar down toward your upper chest, squeezing your shoulder blades together, then let it rise slowly.' },
  { id: 'seated-cable-row', name: 'Seated Cable Row', muscles: ['Back', 'Biceps', 'Shoulders'],
    description: 'A horizontal pulling exercise. Pull the handle toward your torso while keeping your back straight, then extend your arms back out with control.' },
  { id: 'bent-over-row', name: 'Bent Over Row', muscles: ['Back', 'Biceps', 'Shoulders', 'Lower Back'],
    description: 'A compound back exercise. Hinge at the hips with a flat back, then row the bar toward your stomach, squeezing your shoulder blades together.' },
  { id: 'calf-raise', name: 'Calf Raise', muscles: ['Calves'],
    description: 'An isolation exercise for the calves. Rise up onto the balls of your feet as high as you can, then lower your heels slowly back down.' }
];

function initExerciseLibrary() {
  const root = document.getElementById('exercise-root');
  if (!root) return;

  const data = SF.loadData();
  if (!Array.isArray(data.customExercises)) data.customExercises = [];
  initTopbar(data.workouts.length);

  function allExercises() { return [...EXERCISE_LIBRARY, ...data.customExercises]; }

  let selectedMuscles = [];
  let searchTerm = '';

  const listView = document.getElementById('ex-list-view');
  const detailView = document.getElementById('ex-detail-view');

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  /* ---------- list + filtering ---------- */
  function matchesFilters(ex) {
    const nameMatch = ex.name.toLowerCase().includes(searchTerm.toLowerCase());
    const muscleMatch = selectedMuscles.length === 0 || ex.muscles.some(m => selectedMuscles.includes(m));
    return nameMatch && muscleMatch;
  }

  function renderList() {
    const grid = document.getElementById('ex-grid');
    const filtered = allExercises().filter(matchesFilters);
    if (filtered.length === 0) {
      grid.innerHTML = `<div class="empty-state span-all"><div class="empty-state__icon">🔍</div><p class="empty-state__title">No exercises found</p><p class="empty-state__sub">Try a different search or muscle filter.</p></div>`;
    } else {
      grid.innerHTML = filtered.map(ex => `
        <button type="button" class="ex-card" data-ex="${ex.id}">
          <div class="ex-card__thumb">${ex.video ? `<video muted playsinline src="${ex.video}#t=0.1"></video>` : '🏋️'}</div>
          <div class="ex-card__info">
            <h4>${escapeHtml(ex.name)}</h4>
            <p>${ex.muscles.map(escapeHtml).join(', ')}</p>
          </div>
        </button>`).join('');
      grid.querySelectorAll('.ex-card').forEach(card => card.addEventListener('click', () => openDetail(card.dataset.ex)));
    }

    const filterBtn = document.getElementById('muscle-filter-count');
    filterBtn.style.display = selectedMuscles.length ? '' : 'none';
    filterBtn.textContent = selectedMuscles.length;
  }

  document.getElementById('ex-search-input').addEventListener('input', (e) => { searchTerm = e.target.value; renderList(); });

  /* ---------- muscle filter modal ---------- */
  const filterModal = document.getElementById('muscle-filter-modal');
  function renderMuscleOptions() {
    const list = document.getElementById('muscle-option-list');
    list.innerHTML = MUSCLE_LIST.map(m => `<li class="muscle-option${selectedMuscles.includes(m) ? ' is-selected' : ''}" data-muscle="${m}">${m}</li>`).join('');
    list.querySelectorAll('.muscle-option').forEach(li => li.addEventListener('click', () => {
      const m = li.dataset.muscle;
      selectedMuscles = selectedMuscles.includes(m) ? selectedMuscles.filter(x => x !== m) : [...selectedMuscles, m];
      renderMuscleOptions();
      renderList();
    }));
  }
  document.getElementById('open-muscle-filter').addEventListener('click', () => { renderMuscleOptions(); filterModal.style.display = 'flex'; });
  document.getElementById('muscle-filter-close').addEventListener('click', () => { filterModal.style.display = 'none'; });
  filterModal.addEventListener('click', (e) => { if (e.target.id === 'muscle-filter-modal') filterModal.style.display = 'none'; });

  /* ---------- detail view ---------- */
  function openDetail(id) {
    const ex = allExercises().find(e => e.id === id);
    if (!ex) return;
    document.getElementById('ex-detail-title').textContent = ex.name;
    document.getElementById('ex-detail-tags').innerHTML = ex.muscles.map(m => `<span class="ex-detail-tag">${escapeHtml(m)}</span>`).join('');
    document.getElementById('ex-detail-description').textContent = ex.description || 'No description added yet.';
    const media = document.getElementById('ex-detail-media');
    media.innerHTML = ex.video
      ? `<video controls playsinline src="${ex.video}"></video>`
      : `<div class="ex-detail-media__placeholder">🎥<br>Video coming soon</div>`;
    listView.style.display = 'none';
    detailView.style.display = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  document.getElementById('ex-detail-back').addEventListener('click', () => {
    detailView.style.display = 'none';
    listView.style.display = '';
  });

  /* ---------- add custom exercise ---------- */
  const customModal = document.getElementById('custom-ex-modal');
  let customSelectedMuscles = [];

  function renderCustomMuscleChips() {
    const wrap = document.getElementById('custom-ex-muscles');
    wrap.innerHTML = MUSCLE_LIST.map(m => `<button type="button" class="muscle-chip${customSelectedMuscles.includes(m) ? ' is-active' : ''}" data-muscle="${m}">${m}</button>`).join('');
    wrap.querySelectorAll('.muscle-chip').forEach(chip => chip.addEventListener('click', () => {
      const m = chip.dataset.muscle;
      customSelectedMuscles = customSelectedMuscles.includes(m) ? customSelectedMuscles.filter(x => x !== m) : [...customSelectedMuscles, m];
      renderCustomMuscleChips();
    }));
  }

  document.getElementById('open-add-custom-exercise').addEventListener('click', () => {
    customSelectedMuscles = [];
    document.getElementById('custom-ex-name').value = '';
    document.getElementById('custom-ex-description').value = '';
    document.getElementById('custom-ex-video').value = '';
    renderCustomMuscleChips();
    customModal.style.display = 'flex';
  });
  document.getElementById('custom-ex-close').addEventListener('click', () => { customModal.style.display = 'none'; });
  customModal.addEventListener('click', (e) => { if (e.target.id === 'custom-ex-modal') customModal.style.display = 'none'; });

  document.getElementById('custom-ex-save').addEventListener('click', () => {
    const name = document.getElementById('custom-ex-name').value.trim();
    if (!name) { document.getElementById('custom-ex-name').focus(); return; }
    if (customSelectedMuscles.length === 0) { alert('Pick at least one muscle group.'); return; }
    const video = document.getElementById('custom-ex-video').value.trim();
    data.customExercises.push({
      id: uid('cex'),
      name,
      muscles: customSelectedMuscles,
      description: document.getElementById('custom-ex-description').value.trim(),
      video: video || null
    });
    SF.saveData(data);
    customModal.style.display = 'none';
    renderList();
  });

  /* ---------- boot ---------- */
  renderList();
}

/* ---------- start ---------- */
SF.guard();
SF.initTheme();
initSignin();
initSignup();
initHome();
initWorkouts();
initCalendar();
initExerciseLibrary();
