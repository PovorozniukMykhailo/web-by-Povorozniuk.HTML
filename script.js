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
  const emptyData = () => ({ programs: [], workouts: [] });
  const loadData = () => {
    const u = currentUser();
    if (!u) return emptyData();
    const data = read('sf_data_' + u.id, null) || emptyData();
    if (!Array.isArray(data.programs)) data.programs = [];
    if (!Array.isArray(data.workouts)) data.workouts = [];
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

/* ---------- dashboard controller ---------- */
function initHome() {
  const root = document.getElementById('dashboard-root');
  if (!root) return;

  const user = SF.currentUser();
  const data = SF.loadData();
  const workouts = data.workouts;
  const sets = flattenSets(workouts);

  /* ---- topbar ---- */
  const displayName = (user.name && user.name.trim()) || user.email.split('@')[0];
  const initials = displayName.trim().split(/\s+/).slice(0, 2).map(p => p[0].toUpperCase()).join('') || 'U';
  document.getElementById('user-name').textContent = displayName;
  document.getElementById('avatar-initials').textContent = initials;
  document.getElementById('user-level').textContent = 'Level ' + Math.floor(workouts.length / 5);
  document.getElementById('logout-btn').addEventListener('click', SF.logout);

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
    const container = document.getElementById('workouts-list');
    if (list.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state__icon">🏋️</div>
          <p class="empty-state__title">No workouts yet</p>
          <p class="empty-state__sub">Start a workout to see it appear here!</p>
        </div>`;
      return;
    }
    const sorted = [...list].sort((a, b) => (b.finishedAt || b.date).localeCompare(a.finishedAt || a.date)).slice(0, 6);
    container.innerHTML = sorted.map(w => {
      const vol = flattenSets([w]).reduce((sum, s) => sum + s.reps * s.weight, 0);
      return `
        <div class="workout-row">
          <div>
            <div class="workout-row__name">${escapeHtml(w.programName || 'Workout')}</div>
            <div class="workout-row__meta">${w.date} · ${(w.exercises || []).length} exercises</div>
          </div>
          <div class="workout-row__volume">${vol >= 1000 ? (vol / 1000).toFixed(1) + 'k' : vol} kg</div>
        </div>`;
    }).join('');
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
  document.getElementById('start-empty-workout').addEventListener('click', () => { location.href = 'workouts.html'; });

  render();
}

/* ---------- start ---------- */
SF.guard();
SF.initTheme();
initSignin();
initSignup();
initHome();