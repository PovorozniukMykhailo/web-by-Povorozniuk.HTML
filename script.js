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
  const emptyData = () => ({ programs: [], workouts: [], goal: null, customExercises: [], nutritionMeals: [] });
  const loadData = () => {
    const u = currentUser();
    if (!u) return emptyData();
    const data = read('sf_data_' + u.id, null) || emptyData();
    if (!Array.isArray(data.programs)) data.programs = [];
    if (!Array.isArray(data.workouts)) data.workouts = [];
    if (!('goal' in data)) data.goal = null;
    if (!Array.isArray(data.customExercises)) data.customExercises = [];
    if (!Array.isArray(data.nutritionMeals)) data.nutritionMeals = [];
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
const DASH_MUSCLE_KEYS = { Chest: 'badge_chest', Back: 'badge_back', Shoulders: 'badge_shoulders', Arms: 'badge_arms', Legs: 'badge_legs', Core: 'badge_core', Abdomen: 'badge_abdomen' };
function dashMuscleLabel(m) { return I18N.t(DASH_MUSCLE_KEYS[m] || '', m); }

const WEEKDAY_CANONICAL = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const WEEKDAY_KEYS = { Monday: 'weekday_mon', Tuesday: 'weekday_tue', Wednesday: 'weekday_wed', Thursday: 'weekday_thu', Friday: 'weekday_fri', Saturday: 'weekday_sat', Sunday: 'weekday_sun' };
function weekdayLabel(name) { return I18N.t(WEEKDAY_KEYS[name] || '', name); }
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

/* =========================================================
   body-muscles anatomical model (Dashboard)
   ========================================================= */

const ANATOMY_MODEL = {
  frontChart: null,
  backChart: null,
  selectedGroup: null,
  muscleStats: null
};

function anatomyPercentages(muscleStats) {
  const empty = {
    'Head & Neck': 0,
    'Shoulders': 0,
    'Arms': 0,
    'Chest': 0,
    'Back': 0,
    'Abdominals': 0,
    'Legs': 0,
    'Hands & Feet': 0
  };

  if (!muscleStats || !muscleStats.total) return empty;

  const pct = (count) =>
    Math.round((Number(count || 0) / muscleStats.total) * 100);

  return {
    'Head & Neck': 0,
    'Shoulders': pct(muscleStats.counts.Shoulders),
    'Arms': pct(muscleStats.counts.Arms),
    'Chest': pct(muscleStats.counts.Chest),
    'Back': pct(muscleStats.counts.Back),
    'Abdominals': pct(
      Number(muscleStats.counts.Core || 0) +
      Number(muscleStats.counts.Abdomen || 0)
    ),
    'Legs': pct(muscleStats.counts.Legs),
    'Hands & Feet': 0
  };
}

function anatomyGroupForMuscle(muscleId) {
  if (!window.BodyMuscles || !window.BodyMuscles.MUSCLE_GROUPS) return null;

  for (const [groupName, ids] of Object.entries(window.BodyMuscles.MUSCLE_GROUPS)) {
    if (ids.includes(muscleId)) return groupName;
  }

  return null;
}

function buildAnatomyBodyState() {
  if (!window.BodyMuscles || !window.BodyMuscles.MUSCLE_GROUPS) return {};

  const percentages = anatomyPercentages(ANATOMY_MODEL.muscleStats);
  const state = {};

  for (const [groupName, muscleIds] of Object.entries(window.BodyMuscles.MUSCLE_GROUPS)) {
    const percent = percentages[groupName] || 0;
    const trainedIntensity = percent > 0
      ? Math.max(1, Math.min(10, Math.ceil(percent / 10)))
      : 0;

    muscleIds.forEach((muscleId) => {
      const selected = ANATOMY_MODEL.selectedGroup === groupName;

      state[muscleId] = {
        intensity: selected
          ? Math.max(7, trainedIntensity)
          : trainedIntensity,
        selected
      };
    });
  }

  return state;
}

function renderAnatomyModel() {
  const bodyState = buildAnatomyBodyState();

  if (ANATOMY_MODEL.frontChart) {
    ANATOMY_MODEL.frontChart.update({ bodyState });
  }

  if (ANATOMY_MODEL.backChart) {
    ANATOMY_MODEL.backChart.update({ bodyState });
  }

  document.querySelectorAll('[data-anatomy-group]').forEach((button) => {
    button.classList.toggle(
      'is-active',
      Boolean(ANATOMY_MODEL.selectedGroup) &&
      button.dataset.anatomyGroup === ANATOMY_MODEL.selectedGroup
    );
  });

  const hint = document.getElementById('anatomy-hint');

  if (hint) {
    hint.textContent = ANATOMY_MODEL.selectedGroup
      ? `${ANATOMY_MODEL.selectedGroup} selected`
      : 'Select a muscle group to highlight it on the model.';
  }
}

function selectAnatomyGroup(groupName) {
  ANATOMY_MODEL.selectedGroup =
    ANATOMY_MODEL.selectedGroup === groupName
      ? null
      : groupName;

  renderAnatomyModel();
}

function updateAnatomicalMuscleStats(muscleStats) {
  ANATOMY_MODEL.muscleStats = muscleStats;

  const percentages = anatomyPercentages(muscleStats);

  document.querySelectorAll('[data-anatomy-pct]').forEach((element) => {
    const group = element.dataset.anatomyPct;
    element.textContent = `${percentages[group] || 0}%`;
  });

  renderAnatomyModel();
}

function initAnatomicalMuscleMap() {
  const frontEl = document.getElementById('muscle-body-front');
  const backEl = document.getElementById('muscle-body-back');

  if (!frontEl || !backEl) return;

  if (
    !window.BodyMuscles ||
    !window.BodyMuscles.BodyChart ||
    !window.BodyMuscles.ViewSide
  ) {
    const message = `
      <div class="anatomy-load-error">
        Anatomical model could not be loaded.
        Check your internet connection and reload the page.
      </div>
    `;

    frontEl.innerHTML = message;
    backEl.innerHTML = message;

    console.error('body-muscles library was not loaded.');
    return;
  }

  const { BodyChart, ViewSide } = window.BodyMuscles;

  if (ANATOMY_MODEL.frontChart || ANATOMY_MODEL.backChart) return;

  const handleMuscleClick = (muscleId) => {
    const groupName = anatomyGroupForMuscle(muscleId);
    if (groupName) selectAnatomyGroup(groupName);
  };

  ANATOMY_MODEL.frontChart = new BodyChart(frontEl, {
    view: ViewSide.FRONT,
    bodyState: buildAnatomyBodyState(),
    showViewLabel: false,
    enableTransitions: true,
    onMuscleClick: handleMuscleClick
  });

  ANATOMY_MODEL.backChart = new BodyChart(backEl, {
    view: ViewSide.BACK,
    bodyState: buildAnatomyBodyState(),
    showViewLabel: false,
    enableTransitions: true,
    onMuscleClick: handleMuscleClick
  });

  document.querySelectorAll('[data-anatomy-group]').forEach((button) => {
    if (button.dataset.anatomyReady) return;

    button.dataset.anatomyReady = '1';

    button.addEventListener('click', () => {
      selectAnatomyGroup(button.dataset.anatomyGroup);
    });
  });

  const reset = document.getElementById('anatomy-reset');

  if (reset && !reset.dataset.anatomyReady) {
    reset.dataset.anatomyReady = '1';

    reset.addEventListener('click', () => {
      ANATOMY_MODEL.selectedGroup = null;
      renderAnatomyModel();
    });
  }

  renderAnatomyModel();
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

/* =====================================================================
   i18n — language switch (English / Russian)
   ===================================================================== */
const I18N = (() => {
  const KEY = 'sf_lang';

  const dict = {
    ru: {
      // sidebar / topbar
      nav_label: 'Навигация', nav_dashboard: 'Дашборд', nav_workouts: 'Тренировки',
      nav_calendar: 'Календарь', nav_library: 'Библиотека упражнений', nav_nutrition: 'Питание AI', nav_settings: 'Настройки',
      logout: 'Выйти',
      // signin
      signin_title: 'Вход', signin_email_ph: 'Email', signin_password_ph: 'Пароль',
      signin_forgot: 'Забыли пароль?', signin_btn: 'Войти',
      welcome_title: 'Добро пожаловать!', welcome_text: 'Войдите в аккаунт или создайте новый',
      signup_btn: 'Регистрация',
      // signup
      signup_title: 'Регистрация', signup_password_ph: 'Пароль (мин. 8 символов)',
      signup_confirm_ph: 'Подтвердите пароль', signup_btn_create: 'Создать аккаунт',
      signup_have_account: 'Уже есть аккаунт? Войти', welcome_create_text: 'Создайте свой аккаунт',
      // home dashboard
      your_progress: 'Ваш прогресс', metric_volume: 'Объём', metric_sets: 'Подходы', metric_reps: 'Повторения',
      period_week: 'Неделя', period_month: 'Месяц', period_all: 'Всё время',
      stat_workouts: 'Тренировок', stat_volume: 'Общий объём', stat_sets: 'Всего подходов', stat_reps: 'Всего повторений',
      your_records: 'Ваши рекорды', activity: 'Активность', current_streak: 'Текущая серия',
      longest_streak: 'Самая длинная серия', training_days: 'Дней тренировок · за год',
      activity_note: 'Неделя засчитывается, если вы потренировались хотя бы раз. Пропуск дня не сбрасывает серию.',
      favourite_exercise: 'Любимое упражнение', sets_per_week: 'Подходы за неделю',
      sets_per_week_note: 'Считается за последние 7 дней. Каждый подход учитывается в основной группе мышц.',
      muscle_distribution: 'Распределение по мышцам', your_workouts: 'Ваши тренировки',
      badge_chest: 'Грудь', badge_arms: 'Руки', badge_shoulders: 'Плечи', badge_legs: 'Ноги',
      badge_back: 'Спина', badge_core: 'Кор', badge_abdomen: 'Пресс',
      start_empty_workout: '▶ Начать тренировку', no_records: 'Пока нет рекордов — выполните тренировку, чтобы установить первый.',
      no_favourite: 'Пока нет любимого', no_sets_period: 'Нет подходов за этот период.',
      no_workouts_title: 'Пока нет тренировок', no_workouts_sub: 'Начните тренировку, чтобы увидеть её здесь!',
      // workouts.html
      ready_title: 'Готовы тренироваться?', ready_text: 'Начните тренировку с нуля и записывайте упражнения по ходу. Отлично подходит для свободных тренировок.',
      quick_actions: 'Быстрые действия', quick_actions_sub: 'Управляйте своими программами',
      create_plan: '＋ Создать программу', explore_plans: '🏋️ Мои программы',
      your_plans: 'Ваши программы', your_plans_sub: 'Управляйте сохранёнными программами тренировок.',
      history_sub: 'Каждая завершённая тренировка появится здесь и на Дашборде.',
      no_plans_title: 'Пока нет программ', no_plans_sub: 'Создайте свою первую программу тренировок, чтобы начать путь к результату.',
      start_btn: 'Начать', delete_btn: 'Удалить', day_word: 'день', days_word: 'дней',
      no_description: 'Без описания.', untitled_program: 'Программа без названия',
      exercises_configured: 'упражнени(й) добавлено', weekday_mon: 'Понедельник', weekday_tue: 'Вторник',
      weekday_wed: 'Среда', weekday_thu: 'Четверг', weekday_fri: 'Пятница', weekday_sat: 'Суббота', weekday_sun: 'Воскресенье',
      wizard_title: 'Создание программы', wizard_cancel: 'Отмена',
      wizard_step1: 'Детали программы', wizard_step2: 'Тренировочные дни', wizard_step3: 'Обзор и создание',
      wizard_program_title: 'Название программы *', wizard_program_title_ph: 'Введите название программы',
      wizard_description: 'Описание', wizard_description_ph: 'Опишите вашу программу тренировок',
      wizard_difficulty: 'Уровень сложности', wizard_difficulty_ph: 'Выберите уровень сложности',
      wizard_equipment: 'Оборудование', wizard_equipment_ph: 'Выберите тип оборудования',
      wizard_add_templates_title: 'Добавьте тренировочные дни',
      wizard_add_templates_sub: 'Создайте тренировочные дни для программы. Этот шаг можно пропустить и добавить дни позже.',
      wizard_add_template: '+ Добавить ещё день', wizard_add_exercise: '+ Добавить упражнение',
      wizard_review_title: 'Проверьте и создайте', wizard_prev: '← Назад', wizard_next: 'Далее',
      wizard_create: 'Создать программу', of_3: 'из 3',
      session_discard: 'Отменить', session_add_exercise: '+ Добавить упражнение',
      session_finish: '✓ Завершить тренировку', session_default_title: 'Свободная тренировка',
      session_no_exercises: 'Пока нет упражнений — нажмите «Добавить упражнение», чтобы начать запись.',
      session_add_set: '+ Добавить подход', session_name_ph: 'Название упражнения',
      session_reps_ph: 'Повторения', session_weight_ph: 'Вес (кг)',
      // calendar.html
      calendar_title: 'Календарь', workouts_this_month: 'Тренировок в этом месяце',
      legend_completed: 'выполнено', legend_planned: 'запланировано', legend_missed: 'пропущено',
      set_goal: '🎯 Задать цель', edit_goal: '✎ Изменить цель', monthly_goal: 'Цель на месяц',
      plan_workout: '📅 Запланировать тренировку', planned_workout: '📅 Запланированная тренировка',
      missed_workout: '📅 Пропущенная тренировка', no_workouts_day: 'Нет тренировок в этот день',
      goal_modal_title: 'Спланируйте расписание', goal_modal_sub: 'Задайте цель и выберите дни — слоты появятся в календаре.',
      your_goal: 'Ваша цель', month_seg: 'Месяц', week_seg: 'Неделя',
      which_days: 'В какие дни вы тренируетесь?', workout_time: 'Время тренировки',
      save_schedule: 'Сохранить расписание', pick_day: 'Выберите хотя бы один день тренировки.',
      pick_muscle_group: 'Выберите хотя бы одну группу мышц.',
      // exercise.html
      exercise_library: 'Библиотека упражнений', add_custom_exercise: '+ Добавить своё упражнение',
      filter_by_muscle: '🔍 Фильтр по мышцам', search_exercises: 'Поиск упражнений...',
      all_exercises: 'Все упражнения', select_muscle_parts: 'Выберите группы мышц',
      back_to_library: '‹ Назад в библиотеку', no_exercises_found: 'Упражнения не найдены',
      no_exercises_sub: 'Попробуйте изменить поиск или фильтр по мышцам.', video_soon: '🎥 Видео скоро появится',
      custom_ex_title: 'Добавить своё упражнение', custom_ex_sub: 'Добавьте своё упражнение в библиотеку.',
      custom_ex_name: 'Название упражнения', custom_ex_name_ph: 'например, Сведение в кроссовере',
      custom_ex_muscles: 'Задействованные мышцы', custom_ex_desc: 'Описание',
      custom_ex_desc_ph: 'Как выполнять это упражнение', custom_ex_video: 'Имя видеофайла (необязательно)',
      custom_ex_save: 'Сохранить упражнение',
      // misc buttons/toasts
      save: 'Сохранить', cancel: 'Отмена', close: 'Закрыть'
    }
  };

  const muscleDict = {
    ru: {
      Chest: 'Грудь', 'Front Deltoid': 'Передняя дельта', 'Lateral Deltoid': 'Боковая дельта',
      'Rear Deltoid': 'Задняя дельта', Shoulders: 'Плечи', 'Rotator Cuff': 'Ротаторная манжета',
      Triceps: 'Трицепс', Biceps: 'Бицепс', Forearms: 'Предплечья', 'Forearm Flexors': 'Сгибатели предплечья',
      Back: 'Спина', Lats: 'Широчайшие', Trapezius: 'Трапеции', 'Lower Back': 'Низ спины',
      Quadriceps: 'Квадрицепс', Hamstrings: 'Бицепс бедра', Glutes: 'Ягодицы', Adductors: 'Приводящие',
      Calves: 'Икры', Core: 'Кор', Obliques: 'Косые мышцы', 'Hip Flexors': 'Сгибатели бедра'
    }
  };

  const getLang = () => { try { return localStorage.getItem(KEY) === 'ru' ? 'ru' : 'en'; } catch { return 'en'; } };
  const setLang = (lang) => { try { localStorage.setItem(KEY, lang); } catch { /* ignore */ } };

  function t(key, fallback) {
    const lang = getLang();
    if (lang === 'en') return fallback !== undefined ? fallback : key;
    return (dict.ru[key] !== undefined ? dict.ru[key] : (fallback !== undefined ? fallback : key));
  }

  function muscle(name) {
    const lang = getLang();
    if (lang === 'en') return name;
    return muscleDict.ru[name] || name;
  }

  function applyStatic() {
    const lang = getLang();
    if (lang !== 'ru') return; // English is the DOM's default markup, nothing to change
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.dataset.i18n;
      if (dict.ru[key] !== undefined) el.textContent = dict.ru[key];
    });
    document.querySelectorAll('[data-i18n-ph]').forEach(el => {
      const key = el.dataset.i18nPh;
      if (dict.ru[key] !== undefined) el.setAttribute('placeholder', dict.ru[key]);
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.dataset.i18nTitle;
      if (dict.ru[key] !== undefined) el.setAttribute('title', dict.ru[key]);
    });
  }

  function initToggle() {
    const btn = document.getElementById('lang-toggle');
    if (!btn) return;
    const render = () => { btn.textContent = getLang() === 'ru' ? 'EN' : 'RU'; btn.title = getLang() === 'ru' ? 'Switch to English' : 'Переключить на русский'; };
    render();
    btn.addEventListener('click', () => {
      setLang(getLang() === 'ru' ? 'en' : 'ru');
      location.reload();
    });
  }

  return { t, muscle, getLang, setLang, applyStatic, initToggle };
})();

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
  const nameEl =
    document.getElementById('user-name');

  if (!nameEl) return;


  const user =
    SF.currentUser();

  if (!user) return;


  const data =
    SF.loadData();


  const profile =
    data.profile &&
    typeof data.profile === 'object'
      ? data.profile
      : {};


  const displayName =
    (profile.name &&
      profile.name.trim()) ||

    (user.name &&
      user.name.trim()) ||

    user.email.split('@')[0];


  const initials =
    displayName
      .trim()
      .split(/\s+/)
      .slice(0, 2)
      .map(part =>
        part[0].toUpperCase()
      )
      .join('') || 'U';


  nameEl.textContent =
    displayName;


  const avatar =
    document.getElementById(
      'avatar-initials'
    );


  if (avatar) {

    avatar.innerHTML = '';


    if (profile.photo) {

      const image =
        document.createElement(
          'img'
        );


      image.src =
        profile.photo;


      image.alt =
        'Profile photo';


      image.style.width =
        '100%';


      image.style.height =
        '100%';


      image.style.objectFit =
        'cover';


      image.style.borderRadius =
        '50%';


      image.style.display =
        'block';


      avatar.style.overflow =
        'hidden';


      avatar.appendChild(
        image
      );


    } else {

      avatar.textContent =
        initials;


      avatar.style.overflow =
        '';
    }
  }


  const level =
    document.getElementById(
      'user-level'
    );


  if (level) {

    level.textContent =
      'Level ' +
      Math.floor(
        workoutCount / 5
      );
  }


  const logout =
    document.getElementById(
      'logout-btn'
    );


  if (
    logout &&
    !logout.dataset.ready
  ) {

    logout.dataset.ready =
      '1';


    logout.addEventListener(
      'click',
      SF.logout
    );
  }


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
        <p class="empty-state__title">${I18N.t('no_workouts_title', 'No workouts yet')}</p>
        <p class="empty-state__sub">${I18N.t('no_workouts_sub', 'Start a workout to see it appear here!')}</p>
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
      recordsList.innerHTML = `<li class="records-empty">${I18N.t('no_records', 'No records yet — log a workout to set your first.')}</li>`;
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
    document.getElementById('favourite-exercise').textContent = fav ? fav.name : I18N.t('no_favourite', 'No favourite yet');
    document.getElementById('favourite-exercise').classList.toggle('is-empty', !fav);

    /* sets per week + muscle distribution (fixed trailing 7-day window) */
    const muscleStats = computeMuscleStats(sets, 7);
    const setsPerWeekEl = document.getElementById('sets-per-week');
    const withCounts = MUSCLE_GROUPS.filter(m => muscleStats.counts[m] > 0);
    if (withCounts.length === 0) {
      setsPerWeekEl.innerHTML = `<p class="empty-note">${I18N.t('no_sets_period', 'No sets in this period.')}</p>`;
    } else {
      const max = Math.max(...withCounts.map(m => muscleStats.counts[m]));
      setsPerWeekEl.innerHTML = withCounts
        .sort((a, b) => muscleStats.counts[b] - muscleStats.counts[a])
        .map(m => `
          <div class="muscle-bar-row">
            <span class="muscle-bar-row__label">${dashMuscleLabel(m)}</span>
            <div class="muscle-bar-row__track"><div class="muscle-bar-row__fill" style="width:${(muscleStats.counts[m] / max * 100).toFixed(0)}%"></div></div>
            <span class="muscle-bar-row__value">${muscleStats.counts[m]}</span>
          </div>`).join('');
    }
   /* body-muscles anatomical distribution */
    updateAnatomicalMuscleStats(muscleStats);

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
          <p class="empty-state__title">${I18N.t('no_plans_title', 'No workout plans yet')}</p>
          <p class="empty-state__sub">${I18N.t('no_plans_sub', 'Create your first workout plan to get started on your fitness journey.')}</p>
        </div>`;
      list.classList.add('empty-wrap');
      return;
    }
    list.classList.remove('empty-wrap');
    list.innerHTML = data.programs.map(p => `
      <div class="plan-card">
        <h4>${escapeHtml(p.title)}</h4>
        <p>${escapeHtml(p.description || I18N.t('no_description', 'No description.'))}</p>
        <div class="plan-card__tags">
          ${p.difficulty ? `<span class="tag">${escapeHtml(p.difficulty)}</span>` : ''}
          ${p.equipment ? `<span class="tag">${escapeHtml(p.equipment)}</span>` : ''}
          <span class="tag">${p.templates.length} ${I18N.t(p.templates.length === 1 ? 'day_word' : 'days_word', p.templates.length === 1 ? 'day' : 'days')}</span>
        </div>
        <div class="plan-card__actions">
          <button type="button" class="btn btn--primary btn--small" data-start-plan="${p.id}">${I18N.t('start_btn', 'Start')}</button>
          <button type="button" class="btn btn--alt btn--small" data-delete-plan="${p.id}">${I18N.t('delete_btn', 'Delete')}</button>
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
      wizardStep === 1 ? I18N.t('wizard_step1', 'Program Details') : wizardStep === 2 ? I18N.t('wizard_step2', 'Workout Templates') : I18N.t('wizard_step3', 'Review & Create');
    document.getElementById('wizard-step-count').textContent = wizardStep + ' ' + I18N.t('of_3', 'of 3');
    document.getElementById('wizard-progress-fill').style.width = (wizardStep / 3 * 100) + '%';
    document.getElementById('wizard-prev').style.visibility = wizardStep === 1 ? 'hidden' : 'visible';
    document.getElementById('wizard-next').textContent = wizardStep === 3 ? I18N.t('wizard_create', 'Create Program') : I18N.t('wizard_next', 'Next');
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
              ${WEEKDAY_CANONICAL.map(d => `<option value="${d}" ${d === tpl.day ? 'selected' : ''}>${weekdayLabel(d)}</option>`).join('')}
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
const MUSCLE_LIST = ['Chest', 'Front Deltoid', 'Lateral Deltoid', 'Rear Deltoid', 'Shoulders', 'Rotator Cuff', 'Triceps', 'Biceps', 'Forearms', 'Forearm Flexors', 'Back', 'Lats', 'Trapezius', 'Lower Back', 'Quadriceps', 'Hamstrings', 'Glutes', 'Adductors', 'Calves', 'Core', 'Obliques', 'Hip Flexors'];

/* Short reusable description templates, in Russian, adapted per exercise below. */
const D = {
  squat: (extra = '') => `Приседание, нагружающее ноги и ягодицы. Держите спину прямой, опускайтесь, сгибая колени и бёдра, затем поднимайтесь в исходное положение.${extra}`,
  lunge: (extra = '') => `Выпад для ног и ягодиц. Сделайте шаг, опуститесь до угла 90° в обоих коленях, затем вернитесь в исходное положение.${extra}`,
  legCurl: 'Изолирующее упражнение на заднюю поверхность бедра. Согните колени, подтягивая пятки к ягодицам, затем медленно вернитесь обратно.',
  chestPress: 'Жимовое упражнение для груди, плеч и трицепсов. Выжимайте вес от груди вверх или вперёд, затем опускайте с контролем.',
  pushUp: 'Отжимание, укрепляющее грудь, плечи и трицепсы. Опускайтесь до касания грудью опоры, затем мощно выжимайтесь вверх.',
  tricepsExt: 'Изолирующее упражнение на трицепс. Разгибайте руки в локтях, преодолевая сопротивление, затем возвращайтесь в исходное положение.',
  bicepCurl: 'Изолирующее упражнение на бицепс. Согните руки в локтях, поднимая вес к плечам, затем опустите с контролем.',
  row: 'Тяговое упражнение для мышц спины. Тяните вес к корпусу, сводя лопатки, затем медленно возвращайтесь в исходное положение.',
  pulldown: 'Упражнение для широчайших мышц спины. Тяните рукоять или подтягивайтесь, сводя лопатки вместе.',
  hinge: 'Тяговое упражнение с наклоном корпуса. Держите спину прямой, толкайте бёдра назад, затем поднимайтесь, сжимая ягодицы.',
  raise: 'Упражнение для дельтовидных мышц. Поднимайте вес в нужном направлении плавно, без рывков, и опускайте с контролем.',
  rotatorCuff: 'Упражнение для ротаторной манжеты плеча. Выполняйте вращательное движение медленно и подконтрольно, используя лёгкий вес.',
  core: 'Упражнение для мышц кора. Держите корпус в напряжении и контролируйте движение на протяжении всего подхода.',
  explosive: 'Взрывное силовое упражнение для всего тела. Требует хорошей техники — выполняйте только после разминки.',
  calf: 'Изолирующее упражнение для икроножных мышц. Поднимитесь на носки как можно выше, затем медленно опустите пятки вниз.'
};

const EXERCISE_LIBRARY = [
  /* ---------- CHEST ---------- */
  { id: 'bench-press', name: 'Bench Press', muscles: ['Front Deltoid', 'Chest', 'Triceps', 'Biceps'], video: 'bench-press.mp4',
    description: 'Жим лежа — это классическое силовое упражнение, направленное на развитие мышц груди, плеч и трицепсов. Лягте на скамью, возьмитесь за гриф штанги чуть шире плеч, опустите его к груди, а затем мощно поднимитесь вверх. Это упражнение развивает мышечную массу и силу верхней части тела.' },
  { id: 'incline-bench-press', name: 'Incline Bench Press', muscles: ['Chest', 'Triceps', 'Shoulders', 'Biceps'], video: 'Incline-Bench-Press.mp4', description: D.chestPress },
  { id: 'decline-bench-press', name: 'Decline Bench Press', muscles: ['Chest', 'Triceps', 'Shoulders', 'Biceps'], video: 'Decline-Bench-Press.mp4', description: D.chestPress },
  { id: 'chest-fly', name: 'Chest Fly', muscles: ['Chest', 'Shoulders'], video: 'chest-fly.mp4', description: 'Изолирующее упражнение на грудь. Слегка согнув локти, сведите руки перед собой широкой дугой, затем медленно верните в исходное положение.' },
  { id: 'machine-chest-fly', name: 'Machine Chest Fly – Pec Deck', muscles: ['Chest', 'Shoulders'], video: 'MachineChesFlyPecDeck.mp4', description: 'Изолирующее упражнение на грудь в тренажёре. Сведите рукояти перед собой, затем медленно верните их назад с контролем.' },
  { id: 'dumbbell-chest-fly', name: 'Dumbbell Chest Fly', muscles: ['Chest', 'Shoulders'], video: 'dumbellchestfly.mp4', description: 'Изолирующее упражнение на грудь с гантелями. Слегка согнув локти, сведите руки над грудью широкой дугой, затем опустите обратно.' },
  { id: 'resistance-band-chest-fly', name: 'Resistance Band Chest Fly', muscles: ['Chest', 'Shoulders'], video: 'resistancechestfly.mp4', description: 'Сведение рук с резиновой лентой для проработки груди. Держите лёгкий изгиб в локтях и сводите руки перед собой.' },
  { id: 'standing-cable-chest-fly', name: 'Standing Cable Chest Fly', muscles: ['Chest', 'Shoulders'], video: 'standingcablechestfly.mp4', description: 'Сведение рук на блоках стоя. Сведите рукояти перед собой по дуге, затем медленно вернитесь в исходное положение.' },
  { id: 'standing-resistance-band-fly', name: 'Standing Resistance Band Fly', muscles: ['Chest', 'Shoulders'], video: 'standingresistancebandfly.mp4', description: 'Сведение рук с лентой в тренажёре стоя, прорабатывает грудь и плечи с постоянным напряжением.' },
  { id: 'dumbbell-pullover', name: 'Dumbbell Pullover', muscles: ['Chest', 'Shoulders'], video: 'dumbellpullover.mp4', description: 'Лягте на скамью, опустите гантель за голову по дуге, затем верните её над грудью, прорабатывая грудь и широчайшие.' },
  { id: 'cable-crossover', name: 'Cable Crossover', muscles: ['Chest', 'Biceps'], video: 'cablecrossover.mp4', description: 'Сведение рук на верхних блоках. Сведите рукояти перед собой по дуге вниз, прорабатывая внутреннюю часть груди.' },
  { id: 'cable-chest-press', name: 'Cable Chest Press', muscles: ['Chest', 'Shoulders'], video: 'cablechestpress.mp4', description: D.chestPress },
  { id: 'machine-chest-press', name: 'Machine Chest Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'arnold-press', name: 'Arnold Press', muscles: ['Shoulders', 'Chest'], description: 'Жим гантелей с разворотом кистей. Начните с гантелей у плеч ладонями к себе, выжмите вверх, разворачивая ладони наружу.' },

  /* Bench press variations & assistance */
  { id: 'assisted-dip', name: 'Assisted Dip', muscles: ['Front Deltoid', 'Chest', 'Triceps', 'Shoulders'], description: 'Отжимания на брусьях с помощью тренажёра-компенсатора веса. Опускайтесь сгибая локти, затем выжимайтесь вверх.' },
  { id: 'band-assisted-bench-press', name: 'Band-Assisted Bench Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'bar-dip', name: 'Bar Dip', muscles: ['Front Deltoid', 'Chest', 'Triceps', 'Shoulders'], description: 'Отжимания на брусьях. Опуститесь, сгибая локти, наклонив корпус вперёд, затем выжмитесь обратно вверх.' },
  { id: 'bench-press-against-band', name: 'Bench Press Against Band', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'board-press', name: 'Board Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: 'Жим лежа с доской на груди для ограничения амплитуды. Опустите штангу до касания доски, затем выжмите вверх.' },
  { id: 'close-grip-bench-press', name: 'Close-Grip Bench Press', muscles: ['Triceps'], description: 'Жим лежа узким хватом, акцент на трицепс. Опустите штангу к нижней части груди локтями вдоль корпуса, затем выжмите вверх.' },
  { id: 'close-grip-feet-up-bench-press', name: 'Close-Grip Feet-Up Bench Press', muscles: ['Triceps'], description: 'Жим лежа узким хватом с поднятыми ногами для строгой техники и акцента на трицепс.' },
  { id: 'decline-push-up', name: 'Decline Push-Up', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.pushUp },
  { id: 'dumbbell-chest-press', name: 'Dumbbell Chest Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'dumbbell-decline-chest-press', name: 'Dumbbell Decline Chest Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'dumbbell-floor-press', name: 'Dumbbell Floor Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: 'Жим гантелей лёжа на полу — ограниченная амплитуда снижает нагрузку на плечи, акцент на грудь и трицепс.' },
  { id: 'feet-up-bench-press', name: 'Feet-Up Bench Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'floor-press', name: 'Floor Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: 'Жим лёжа на полу с гантелями или штангой, укороченная амплитуда снижает нагрузку на плечевой сустав.' },
  { id: 'incline-dumbbell-press', name: 'Incline Dumbbell Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'incline-push-up', name: 'Incline Push-Up', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.pushUp },
  { id: 'kettlebell-floor-press', name: 'Kettlebell Floor Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: 'Жим гирь лёжа на полу, укороченная амплитуда для акцента на грудь и трицепс.' },
  { id: 'kneeling-incline-push-up', name: 'Kneeling Incline Push-Up', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.pushUp },
  { id: 'kneeling-push-up', name: 'Kneeling Push-Up', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.pushUp },
  { id: 'pin-bench-press', name: 'Pin Bench Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: 'Жим лежа со старта со штангой на упорах, убирает инерцию и требует силы с самого начала движения.' },
  { id: 'push-up', name: 'Push-Up', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.pushUp },
  { id: 'push-up-against-wall', name: 'Push-Up Against Wall', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.pushUp },
  { id: 'push-ups-with-feet-in-rings', name: 'Push-Ups With Feet in Rings', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.pushUp },
  { id: 'ring-dip', name: 'Ring Dip', muscles: ['Chest', 'Triceps', 'Shoulders'], description: 'Отжимания на гимнастических кольцах — требуют стабилизации, прорабатывают грудь, плечи и трицепс.' },
  { id: 'smith-machine-bench-press', name: 'Smith Machine Bench Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'smith-machine-incline-bench-press', name: 'Smith Machine Incline Bench Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'smith-machine-reverse-grip-bench-press', name: 'Smith Machine Reverse Grip Bench Press', muscles: ['Front Deltoid', 'Chest', 'Shoulders'], description: D.chestPress },
  { id: 'close-grip-push-up', name: 'Close-Grip Push-Up', muscles: ['Triceps'], description: 'Отжимания узким хватом с акцентом на трицепс. Держите локти близко к корпусу на всём движении.' },

  /* ---------- TRICEPS ---------- */
  { id: 'tricep-dip', name: 'Tricep Dip', muscles: ['Chest', 'Triceps', 'Shoulders'], video: 'tricep-dip.mp4', description: 'Отжимания на брусьях или скамье для трицепса. Опустите тело, сгибая локти, затем выжмитесь обратно вверх.' },
  { id: 'skull-crusher', name: 'Skull Crusher', muscles: ['Triceps', 'Shoulders'], description: D.tricepsExt },
  { id: 'dumbbell-lying-triceps-ext', name: 'Dumbbell Lying Triceps Extension', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'dumbbell-standing-triceps-ext', name: 'Dumbbell Standing Triceps Extension', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'overhead-cable-triceps-ext', name: 'Overhead Cable Triceps Extension', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'tricep-bodyweight-ext', name: 'Tricep Bodyweight Extension', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'tricep-pushdown-bar', name: 'Tricep Pushdown With Bar', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'tricep-pushdown-rope', name: 'Tricep Pushdown With Rope', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'barbell-standing-triceps-ext', name: 'Barbell Standing Triceps Extension', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'barbell-lying-triceps-ext', name: 'Barbell Lying Triceps Extension', muscles: ['Triceps'], description: D.tricepsExt },
  { id: 'bench-dip', name: 'Bench Dip', muscles: ['Triceps'], description: 'Отжимания от скамьи для трицепса. Опустите таз вниз, сгибая локти, затем выжмитесь обратно вверх.' },
  { id: 'crossbody-cable-triceps-ext', name: 'Crossbody Cable Triceps Extension', muscles: ['Triceps'], description: D.tricepsExt },

  /* ---------- LEGS: QUADS / GLUTES / ADDUCTORS ---------- */
  { id: 'squat', name: 'Squat', muscles: ['Quadriceps', 'Glutes', 'Hamstrings', 'Calves'], video: 'squat.mp4', description: D.squat() },
  { id: 'leg-press', name: 'Leg Press', muscles: ['Quadriceps', 'Glutes', 'Hamstrings'], video: 'leg-press.mp4', description: 'Жим ногами в тренажёре. Толкайте платформу, разгибая колени и бёдра, затем возвращайтесь под контролем, не блокируя колени полностью.' },
  { id: 'lunge', name: 'Lunge', muscles: ['Quadriceps', 'Glutes', 'Hamstrings', 'Calves'], description: D.lunge() },
  { id: 'leg-extension', name: 'Leg Extension', muscles: ['Quadriceps', 'Glutes'], description: 'Изолирующее упражнение на квадрицепс в тренажёре. Разогните колени, поднимая валик, затем медленно опустите обратно.' },
  { id: 'front-squat', name: 'Front Squat', muscles: ['Quadriceps', 'Glutes', 'Hamstrings', 'Calves'], description: D.squat(' Штанга удерживается спереди на плечах.') },
  { id: 'overhead-squat', name: 'Overhead Squat', muscles: ['Quadriceps', 'Glutes', 'Hamstrings', 'Shoulders'], description: D.squat(' Штанга удерживается на прямых руках над головой.') },
  { id: 'air-squat', name: 'Air Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Выполняется без отягощения.') },
  { id: 'barbell-lunge', name: 'Barbell Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Штанга удерживается на плечах.') },
  { id: 'barbell-walking-lunge', name: 'Barbell Walking Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], video: 'unge-walking.mp4', description: D.lunge(' Выполняется шагами вперёд, поочерёдно меняя ногу.') },
  { id: 'belt-squat', name: 'Belt Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Нагрузка крепится на пояс, снимая её со спины.') },
  { id: 'body-weight-lunge', name: 'Body Weight Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Выполняется без отягощения.') },
  { id: 'box-jump', name: 'Box Jump', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: 'Взрывной прыжок на возвышение. Присядьте, оттолкнитесь и запрыгните на бокс двумя ногами, мягко приземлившись.' },
  { id: 'box-squat', name: 'Box Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' Внизу лёгкое касание ящика помогает контролировать глубину.') },
  { id: 'bulgarian-split-squat', name: 'Bulgarian Split Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: 'Присед на одной ноге с задней ногой на возвышении. Опускайтесь, сгибая переднее колено, затем поднимайтесь обратно.' },
  { id: 'chair-squat', name: 'Chair Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Лёгкое касание стула снизу помогает контролировать глубину и технику.') },
  { id: 'dumbbell-lunge', name: 'Dumbbell Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Гантели удерживаются в опущенных руках.') },
  { id: 'dumbbell-squat', name: 'Dumbbell Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' Гантели удерживаются у плеч или вдоль корпуса.') },
  { id: 'goblet-squat', name: 'Goblet Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Гантеля или гиря удерживается у груди обеими руками.') },
  { id: 'hack-squat-machine', name: 'Hack Squat Machine', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Выполняется в тренажёре с фиксированной траекторией движения.') },
  { id: 'half-air-squat', name: 'Half Air Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Выполняется на неполную амплитуду без отягощения.') },
  { id: 'hip-adduction-machine', name: 'Hip Adduction Machine', muscles: ['Adductors'], description: 'Изолирующее упражнение на приводящие мышцы бедра в тренажёре. Сведите ноги, преодолевая сопротивление, затем медленно разведите обратно.' },
  { id: 'jumping-lunge', name: 'Jumping Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Смена ног происходит в прыжке.') },
  { id: 'landmine-hack-squat', name: 'Landmine Hack Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Выполняется со штангой в упоре landmine за спиной.') },
  { id: 'landmine-squat', name: 'Landmine Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.squat(' Штанга в упоре landmine удерживается двумя руками у груди.') },
  { id: 'pause-squat', name: 'Pause Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' В нижней точке выполняется пауза перед подъёмом.') },
  { id: 'pistol-squat', name: 'Pistol Squat', muscles: ['Quadriceps', 'Glutes'], description: 'Присед на одной ноге со свободной ногой вытянутой вперёд. Требует силы и баланса.' },
  { id: 'reverse-barbell-lunge', name: 'Reverse Barbell Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Шаг выполняется назад, штанга удерживается на плечах.') },
  { id: 'reverse-body-weight-lunge', name: 'Reverse Body Weight Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Шаг выполняется назад, без отягощения.') },
  { id: 'reverse-dumbbell-lunge', name: 'Reverse Dumbbell Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Шаг выполняется назад, с гантелями в руках.') },
  { id: 'safety-bar-squat', name: 'Safety Bar Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' Выполняется со специальным грифом safety bar на плечах.') },
  { id: 'shallow-body-weight-lunge', name: 'Shallow Body Weight Lunge', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: D.lunge(' Выполняется на неполную амплитуду.') },
  { id: 'side-lunges-bodyweight', name: 'Side Lunges (Bodyweight)', muscles: ['Quadriceps', 'Glutes'], description: 'Выпад в сторону без отягощения, прорабатывающий квадрицепс и ягодицы, а также приводящие мышцы бедра.' },
  { id: 'smith-machine-bulgarian-split-squat', name: 'Smith Machine Bulgarian Split Squat', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: 'Болгарский сплит-присед в тренажёре Смита с фиксированной траекторией штанги.' },
  { id: 'smith-machine-front-squat', name: 'Smith Machine Front Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' Штанга спереди, выполняется в тренажёре Смита.') },
  { id: 'smith-machine-squat', name: 'Smith Machine Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' Выполняется в тренажёре Смита с фиксированной траекторией.') },
  { id: 'step-up', name: 'Step Up', muscles: ['Adductors', 'Quadriceps', 'Glutes'], description: 'Шаг на возвышение с подъёмом тела одной ногой, прорабатывает квадрицепс и ягодицы.' },
  { id: 'zercher-squat', name: 'Zercher Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' Штанга удерживается в сгибе локтей перед корпусом.') },
  { id: 'zombie-squat', name: 'Zombie Squat', muscles: ['Lower Back', 'Adductors', 'Quadriceps', 'Glutes', 'Forearms'], description: D.squat(' Штанга удерживается на вытянутых вперёд руках.') },
  { id: 'calf-raise', name: 'Calf Raise', muscles: ['Calves'], description: D.calf },
  { id: 'seated-calf-raise', name: 'Seated Calf Raise', muscles: ['Calves', 'Quadriceps'], description: D.calf },

  /* ---------- HAMSTRINGS ---------- */
  { id: 'leg-curl', name: 'Leg Curl', muscles: ['Hamstrings', 'Glutes'], description: D.legCurl },
  { id: 'bodyweight-leg-curl', name: 'Bodyweight Leg Curl', muscles: ['Hamstrings'], description: D.legCurl },
  { id: 'glute-ham-raise', name: 'Glute Ham Raise', muscles: ['Hamstrings'], description: 'Сгибание корпуса с фиксированными ногами в тренажёре GHR, сильная нагрузка на заднюю поверхность бедра.' },
  { id: 'leg-curl-on-ball', name: 'Leg Curl On Ball', muscles: ['Hamstrings'], description: D.legCurl },
  { id: 'lying-leg-curl', name: 'Lying Leg Curl', muscles: ['Hamstrings'], description: D.legCurl },
  { id: 'nordic-hamstring-eccentric', name: 'Nordic Hamstring Eccentric', muscles: ['Hamstrings'], description: 'Эксцентрическое упражнение на бицепс бедра стоя на коленях с зафиксированными стопами — медленно наклоняйтесь вперёд.' },
  { id: 'romanian-deadlift', name: 'Romanian Deadlift', muscles: ['Lower Back', 'Glutes', 'Hamstrings', 'Forearms'], description: D.hinge },
  { id: 'seated-leg-curl', name: 'Seated Leg Curl', muscles: ['Hamstrings'], description: D.legCurl },
  { id: 'deadlift', name: 'Deadlift', muscles: ['Glutes', 'Hamstrings', 'Back', 'Forearms'], video: 'deadlift.mp4', description: 'Становая тяга — базовое упражнение для всего тела. Возьмитесь за гриф чуть шире ног, держите спину прямой и поднимитесь, толкая бёдра вперёд.' },
  { id: 'hip-thrust', name: 'Hip Thrust', muscles: ['Glutes', 'Hamstrings', 'Lower Back'], description: 'Ягодичный мост со штангой на бёдрах, спина опирается на скамью. Поднимите таз вверх, сжимая ягодицы, затем опустите обратно.' },
  { id: 'good-morning', name: 'Good Morning', muscles: ['Glutes', 'Lower Back', 'Hamstrings', 'Shoulders'], description: D.hinge },

  /* ---------- BACK / LATS ---------- */
  { id: 'pull-up', name: 'Pull Up', muscles: ['Biceps', 'Back', 'Shoulders'], video: 'pull-ups.mp4', description: 'Подтягивание на перекладине. Повисните хватом от себя, подтянитесь подбородком выше перекладины, затем медленно опуститесь.' },
  { id: 'lat-pulldown', name: 'Lat Pulldown', muscles: ['Biceps', 'Back', 'Forearms'], description: D.pulldown },
  { id: 'seated-cable-row', name: 'Seated Cable Row', muscles: ['Biceps', 'Back', 'Forearms'], description: D.row },
  { id: 'bent-over-row', name: 'Bent Over Row', muscles: ['Biceps', 'Back', 'Lower Back'], description: D.row },
  { id: 'face-pull', name: 'Face Pull', muscles: ['Shoulders', 'Back'], description: 'Тяга каната к лицу на верхнем блоке, разводя локти в стороны — укрепляет заднюю дельту и мышцы спины.' },
  { id: 'assisted-chin-up', name: 'Assisted Chin-Up', muscles: ['Lats'], description: 'Подтягивание обратным хватом с компенсацией веса тела в тренажёре.' },
  { id: 'assisted-pull-up', name: 'Assisted Pull-Up', muscles: ['Lats'], description: 'Подтягивание прямым хватом с компенсацией веса тела в тренажёре.' },
  { id: 'back-extension', name: 'Back Extension', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: 'Разгибание корпуса на тренажёре для нижней части спины и ягодиц, выполняется с прямой спиной.' },
  { id: 'banded-muscle-up', name: 'Banded Muscle-Up', muscles: ['Chest', 'Triceps', 'Lats', 'Shoulders'], description: D.explosive },
  { id: 'barbell-row', name: 'Barbell Row', muscles: ['Rear Deltoid', 'Lats', 'Trapezius'], description: D.row },
  { id: 'barbell-shrug', name: 'Barbell Shrug', muscles: ['Trapezius'], description: 'Пожимание плечами со штангой в опущенных руках, изолированно нагружает трапеции.' },
  { id: 'block-clean', name: 'Block Clean', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: D.explosive },
  { id: 'block-snatch', name: 'Block Snatch', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: D.explosive },
  { id: 'jefferson-curl', name: 'Jefferson Curl', muscles: ['Lower Back', 'Forearms'], description: 'Медленное скручивание позвоночника вперёд с лёгким весом для мобильности и укрепления нижней части спины.' },
  { id: 'jumping-muscle-up', name: 'Jumping Muscle-Up', muscles: ['Chest', 'Triceps', 'Lats', 'Shoulders'], description: D.explosive },
  { id: 'kettlebell-swing', name: 'Kettlebell Swing', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: 'Маховое движение гирей от бёдер, взрывное разгибание тазобедренных суставов.' },
  { id: 'lat-pulldown-pronated', name: 'Lat Pulldown With Pronated Grip', muscles: ['Lats'], description: D.pulldown },
  { id: 'lat-pulldown-supinated', name: 'Lat Pulldown With Supinated Grip', muscles: ['Lats'], description: D.pulldown },
  { id: 'muscle-up-bar', name: 'Muscle-Up (Bar)', muscles: ['Chest', 'Triceps', 'Lats', 'Shoulders'], description: D.explosive },
  { id: 'muscle-up-rings', name: 'Muscle-Up (Rings)', muscles: ['Chest', 'Triceps', 'Lats', 'Shoulders'], description: D.explosive },
  { id: 'one-handed-cable-row', name: 'One-Handed Cable Row', muscles: ['Rear Deltoid', 'Lats', 'Trapezius'], description: D.row },
  { id: 'one-handed-lat-pulldown', name: 'One-Handed Lat Pulldown', muscles: ['Lats'], description: D.pulldown },
  { id: 'pause-deadlift', name: 'Pause Deadlift', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: D.hinge },
  { id: 'pendlay-row', name: 'Pendlay Row', muscles: ['Rear Deltoid', 'Lats', 'Trapezius'], description: D.row },
  { id: 'power-clean', name: 'Power Clean', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: D.explosive },
  { id: 'power-snatch', name: 'Power Snatch', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: D.explosive },
  { id: 'pull-up-neutral-grip', name: 'Pull-Up With a Neutral Grip', muscles: ['Lats'], description: 'Подтягивание нейтральным хватом ладонями друг к другу — прорабатывает широчайшие мышцы спины.' },
  { id: 'rack-pull', name: 'Rack Pull', muscles: ['Lower Back', 'Glutes', 'Forearms'], description: D.hinge },
  { id: 'ring-pull-up', name: 'Ring Pull-Up', muscles: ['Lats'], description: 'Подтягивание на гимнастических кольцах — требует стабилизации, прорабатывает широчайшие мышцы спины.' },
  { id: 'ring-row', name: 'Ring Row', muscles: ['Rear Deltoid', 'Lats', 'Trapezius'], description: D.row },
  { id: 'scap-pull-up', name: 'Scap Pull-Up', muscles: ['Rotator Cuff', 'Forearm Flexors'], description: 'Подтягивание лопаток на прямых руках — укрепляет плечевой пояс без сгибания локтей.' },
  { id: 'seal-row', name: 'Seal Row', muscles: ['Rear Deltoid', 'Lats', 'Trapezius'], description: D.row },
  { id: 'seated-machine-row', name: 'Seated Machine Row', muscles: ['Rear Deltoid', 'Lats', 'Trapezius'], description: D.row },
  { id: 'single-leg-deadlift-kettlebell', name: 'Single Leg Deadlift with Kettlebell', muscles: ['Lower Back', 'Glutes', 'Hamstrings', 'Forearms'], description: D.hinge },
  { id: 'hyperextension', name: 'Hyperextension', muscles: ['Glutes', 'Lower Back', 'Hamstrings', 'Back'], description: 'Разгибание корпуса на тренажёре для нижней части спины — опустите корпус вперёд, затем поднимите в прямую линию.' },

  /* ---------- SHOULDERS ---------- */
  { id: 'shoulder-press', name: 'Shoulder Press', muscles: ['Triceps', 'Shoulders', 'Chest'], video: 'Shoulder-Press.mp4', description: 'Жим гантелей или штанги над головой. Выжмите вес вверх до полного выпрямления рук, затем опустите с контролем.' },
  { id: 'behind-the-neck-press', name: 'Behind the Neck Press', muscles: ['Front Deltoid', 'Lateral Deltoid'], description: D.raise },
  { id: 'overhead-press', name: 'Overhead Press', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'push-press', name: 'Push Press', muscles: ['Front Deltoid'], description: 'Жим штанги над головой с помощью небольшого импульса ног — позволяет работать с большим весом.' },
  { id: 'power-jerk', name: 'Power Jerk', muscles: ['Front Deltoid'], description: D.explosive },
  { id: 'cuban-press', name: 'Cuban Press', muscles: ['Front Deltoid'], description: 'Комплексное упражнение для плеч, сочетающее тягу, вращение и жим — укрепляет весь плечевой пояс.' },
  { id: 'front-hold', name: 'Front Hold', muscles: ['Front Deltoid'], description: 'Статическое удержание веса на вытянутых вперёд руках, укрепляет переднюю дельту и стабилизаторы.' },
  { id: 'plate-front-raise', name: 'Plate Front Raise', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'barbell-front-raise', name: 'Barbell Front Raise', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'dumbbell-front-raise', name: 'Dumbbell Front Raise', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'seated-dumbbell-shoulder-press', name: 'Seated Dumbbell Shoulder Press', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'seated-barbell-overhead-press', name: 'Seated Barbell Overhead Press', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'seated-smith-machine-shoulder-press', name: 'Seated Smith Machine Shoulder Press', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'snatch-grip-behind-neck-press', name: 'Snatch Grip Behind the Neck Press', muscles: ['Front Deltoid', 'Lateral Deltoid'], description: D.raise },
  { id: 'dumbbell-shoulder-press', name: 'Dumbbell Shoulder Press', muscles: ['Front Deltoid'], description: D.raise },
  { id: 'barbell-upright-row', name: 'Barbell Upright Row', muscles: ['Lateral Deltoid'], description: 'Тяга штанги к подбородку узким хватом — прорабатывает боковую дельту и трапеции.' },
  { id: 'cable-lateral-raise', name: 'Cable Lateral Raise', muscles: ['Lateral Deltoid'], description: D.raise },
  { id: 'dumbbell-lateral-raise', name: 'Dumbbell Lateral Raise', muscles: ['Lateral Deltoid'], description: D.raise },
  { id: 'monkey-row', name: 'Monkey Row', muscles: ['Lateral Deltoid'], description: 'Тяга гантелей в стороны с наклоном корпуса — акцент на боковую дельту.' },
  { id: 'barbell-rear-delt-row', name: 'Barbell Rear Delt Row', muscles: ['Rear Deltoid', 'Trapezius'], description: D.row },
  { id: 'dumbbell-rear-delt-row', name: 'Dumbbell Rear Delt Row', muscles: ['Rear Deltoid', 'Trapezius'], description: D.row },
  { id: 'reverse-cable-flyes', name: 'Reverse Cable Flyes', muscles: ['Rotator Cuff', 'Rear Deltoid'], description: 'Разведение рук на блоках в наклоне — прорабатывает заднюю дельту и ротаторную манжету.' },
  { id: 'reverse-dumbbell-flyes', name: 'Reverse Dumbbell Flyes', muscles: ['Rotator Cuff', 'Rear Deltoid'], description: 'Разведение гантелей в наклоне — прорабатывает заднюю дельту и ротаторную манжету.' },
  { id: 'reverse-machine-fly', name: 'Reverse Machine Fly', muscles: ['Rotator Cuff', 'Rear Deltoid'], description: 'Разведение рук в тренажёре обратным хватом для задней дельты.' },
  { id: 'band-external-shoulder-rotation', name: 'Band External Shoulder Rotation', muscles: ['Rotator Cuff'], description: D.rotatorCuff },
  { id: 'band-internal-shoulder-rotation', name: 'Band Internal Shoulder Rotation', muscles: ['Rotator Cuff'], description: D.rotatorCuff },
  { id: 'band-pull-apart', name: 'Band Pull-Apart', muscles: ['Rotator Cuff', 'Rear Deltoid'], description: 'Разведение резиновой ленты перед собой прямыми руками — укрепляет заднюю дельту и ротаторную манжету.' },
  { id: 'dumbbell-horizontal-internal-rotation', name: 'Dumbbell Horizontal Internal Rotation', muscles: ['Rotator Cuff'], description: D.rotatorCuff },
  { id: 'dumbbell-horizontal-external-rotation', name: 'Dumbbell Horizontal External Rotation', muscles: ['Rotator Cuff'], description: D.rotatorCuff },
  { id: 'cable-rear-delt-row', name: 'Cable Rear Delt Row', muscles: ['Rotator Cuff', 'Rear Deltoid'], description: D.row },

  /* ---------- BICEPS ---------- */
  { id: 'bicep-curl', name: 'Bicep Curl', muscles: ['Biceps', 'Forearms'], video: 'bicep-curl.mp4', description: 'Сгибание рук с гантелями для бицепса. Держите локти прижатыми к корпусу, поднимите вес к плечам, затем опустите с контролем.' },
  { id: 'hammer-curl', name: 'Hammer Curl', muscles: ['Biceps', 'Forearms'], description: D.bicepCurl },
  { id: 'barbell-preacher-curl', name: 'Barbell Preacher Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'bayesian-curl', name: 'Bayesian Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'bodyweight-curl', name: 'Bodyweight Curl', muscles: ['Biceps', 'Lats'], description: 'Сгибание рук с использованием собственного веса тела на низкой перекладине или TRX.' },
  { id: 'cable-crossover-bicep-curl', name: 'Cable Crossover Bicep Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'cable-curl-with-bar', name: 'Cable Curl With Bar', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'cable-curl-with-rope', name: 'Cable Curl With Rope', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'concentration-curl', name: 'Concentration Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'drag-curl', name: 'Drag Curl', muscles: ['Biceps'], description: 'Сгибание рук со штангой, скользя грифом вдоль корпуса — снижает участие плеча, акцент на бицепс.' },
  { id: 'dumbbell-curl', name: 'Dumbbell Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'dumbbell-preacher-curl', name: 'Dumbbell Preacher Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'incline-dumbbell-curl', name: 'Incline Dumbbell Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'machine-bicep-curl', name: 'Machine Bicep Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'resistance-band-curl', name: 'Resistance Band Curl', muscles: ['Biceps'], description: D.bicepCurl },
  { id: 'spider-curl', name: 'Spider Curl', muscles: ['Biceps'], description: D.bicepCurl },

  /* ---------- CORE ---------- */
  { id: 'plank', name: 'Plank', muscles: ['Core', 'Shoulders'], description: 'Статическое удержание тела на предплечьях и носках в прямой линии — укрепляет мышцы кора.' },
  { id: 'russian-twist', name: 'Russian Twist', muscles: ['Core', 'Obliques', 'Hip Flexors'], description: 'Скручивание корпуса в стороны сидя с приподнятыми ногами — прорабатывает косые мышцы живота.' },
  { id: 'leg-raise', name: 'Leg Raise', muscles: ['Core', 'Hip Flexors', 'Obliques'], description: 'Подъём прямых ног в висе или лёжа — прорабатывает нижнюю часть пресса и сгибатели бедра.' },
  { id: 'bicycle-crunch', name: 'Bicycle Crunch', muscles: ['Core', 'Obliques', 'Hip Flexors', 'Shoulders'], description: D.core }
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
          <div class="ex-card__thumb">${ex.video ? `<video muted autoplay loop playsinline preload="metadata" src="${ex.video}"></video>` : '🏋️'}</div>
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
  ? `<video controls playsinline preload="metadata" src="${ex.video}"></video>`
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
/* =========================================================
   AI FITNESS ASSISTANT
   ========================================================= */


/* =========================================================
   APP TOASTS
   ========================================================= */

function showAppToast(
  message,
  {
    type = 'success',
    duration = 4200,
    actionText = '',
    onAction = null
  } = {}
) {

  let stack =
    document.getElementById(
      'app-toast-stack'
    );

  if (!stack) {
    stack =
      document.createElement(
        'div'
      );

    stack.id =
      'app-toast-stack';

    stack.className =
      'app-toast-stack';

    stack.setAttribute(
      'aria-live',
      'polite'
    );

    stack.setAttribute(
      'aria-atomic',
      'true'
    );

    document.body.appendChild(
      stack
    );
  }


  const toast =
    document.createElement(
      'div'
    );

  toast.className =
    `app-toast app-toast--${type}`;


  const icon =
    document.createElement(
      'span'
    );

  icon.className =
    'app-toast__icon';

  icon.textContent =
    type === 'success'
      ? '✓'
      : '!';


  const text =
    document.createElement(
      'div'
    );

  text.className =
    'app-toast__text';

  text.textContent =
    message;


  toast.appendChild(icon);
  toast.appendChild(text);


  if (
    actionText &&
    typeof onAction === 'function'
  ) {

    const action =
      document.createElement(
        'button'
      );

    action.type =
      'button';

    action.className =
      'app-toast__action';

    action.textContent =
      actionText;

    action.addEventListener(
      'click',
      () => {
        onAction();
        close();
      }
    );

    toast.appendChild(
      action
    );
  }


  const close = () => {

    if (
      toast.classList.contains(
        'is-leaving'
      )
    ) {
      return;
    }

    toast.classList.add(
      'is-leaving'
    );

    setTimeout(
      () => toast.remove(),
      280
    );
  };


  stack.appendChild(
    toast
  );


  requestAnimationFrame(
    () => {
      toast.classList.add(
        'is-visible'
      );
    }
  );


  window.setTimeout(
    close,
    duration
  );

}


function initAIAssistant() {

  if (
    document.body.dataset.auth !== 'required'
  ) {
    return;
  }


  if (
    document.body.dataset.page === 'payment'
  ) {
    return;
  }


  if (
    document.getElementById(
      'ai-assistant-toggle'
    )
  ) {
    return;
  }


  const user =
    SF.currentUser();


  if (!user) {
    return;
  }


  const FREE_LIMIT = 2;

  const WINDOW_MS =
    12 * 60 * 60 * 1000;


  const data =
    SF.loadData();


  if (
    !data.aiAssistant ||
    typeof data.aiAssistant !== 'object'
  ) {

    data.aiAssistant = {};
  }


  const aiState =
    data.aiAssistant;


  if (
    !Number.isFinite(
      Number(aiState.used)
    )
  ) {

    aiState.used = 0;
  }


  aiState.used =
    Number(aiState.used);


  if (!aiState.windowStartedAt) {

    aiState.windowStartedAt =
      Date.now();
  }


  if (
    !('subscriptionUntil' in aiState)
  ) {

    aiState.subscriptionUntil = null;
  }


  function saveAIData() {

    return SF.saveData(data);
  }


  function resetWindowIfNeeded() {

    const started =
      Number(
        aiState.windowStartedAt
      );


    if (
      !started ||
      Date.now() - started >= WINDOW_MS
    ) {

      aiState.used = 0;

      aiState.windowStartedAt =
        Date.now();

      saveAIData();
    }
  }


  function subscriptionEndTime() {

    if (!aiState.subscriptionUntil) {
      return 0;
    }


    const result =
      Date.parse(
        aiState.subscriptionUntil
      );


    return Number.isFinite(result)
      ? result
      : 0;
  }


  function isPro() {

    return (
      subscriptionEndTime() >
      Date.now()
    );
  }


  function remainingRequests() {

    resetWindowIfNeeded();

    return Math.max(
      0,
      FREE_LIMIT - aiState.used
    );
  }


  function remainingWindowText() {

    resetWindowIfNeeded();


    const end =
      Number(
        aiState.windowStartedAt
      ) + WINDOW_MS;


    const difference =
      Math.max(
        0,
        end - Date.now()
      );


    const hours =
      Math.floor(
        difference /
        (60 * 60 * 1000)
      );


    const minutes =
      Math.floor(
        (
          difference %
          (60 * 60 * 1000)
        ) /
        (60 * 1000)
      );


    return `${hours}ч ${minutes}м`;
  }


  const toggle =
    document.createElement(
      'button'
    );


  toggle.type =
    'button';


  toggle.id =
    'ai-assistant-toggle';


  toggle.className =
    'ai-toggle';


 toggle.innerHTML = '🤖';


  toggle.title =
    'AI Fitness Assistant';


  toggle.setAttribute(
    'aria-label',
    'AI Fitness Assistant'
  );


  document.body.appendChild(
    toggle
  );


  const modal =
    document.createElement(
      'div'
    );


  modal.id =
    'ai-assistant-modal';


  modal.className =
    'ai-modal';


  modal.hidden =
    true;


  modal.innerHTML = `

    <div
      class="ai-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-assistant-title"
    >

      <div class="ai-card__top">

        <div>

          <h2
            class="ai-card__title"
            id="ai-assistant-title"
          >
            🤖 AI Fitness Assistant
          </h2>

          <p class="ai-card__subtitle">
            Расскажи о себе и выбери мышцы.
            Я создам тренировку и сохраню
            её в Workouts.
          </p>

        </div>


        <button
          type="button"
          class="ai-close"
          id="ai-assistant-close"
        >
          ✕
        </button>

      </div>


      <div
        class="ai-status"
        id="ai-request-status"
      ></div>


      <div id="ai-form-view">

        <div class="ai-form-grid">

          <div class="ai-field">

            <label for="ai-age">
              Возраст
            </label>

            <input
              id="ai-age"
              type="number"
              min="10"
              max="100"
              placeholder="18"
            >

          </div>


          <div class="ai-field">

            <label for="ai-height">
              Рост, см
            </label>

            <input
              id="ai-height"
              type="number"
              min="100"
              max="250"
              placeholder="175"
            >

          </div>


          <div class="ai-field">

            <label for="ai-weight">
              Вес, кг
            </label>

            <input
              id="ai-weight"
              type="number"
              min="30"
              max="300"
              step="0.1"
              placeholder="70"
            >

          </div>


          <div class="ai-field">

            <label for="ai-experience">
              Опыт
            </label>

            <select id="ai-experience">

              <option value="beginner">
                Beginner
              </option>

              <option value="intermediate">
                Intermediate
              </option>

              <option value="advanced">
                Advanced
              </option>

            </select>

          </div>


          <div class="ai-field">

            <label for="ai-goal">
              Цель
            </label>

            <select id="ai-goal">

              <option value="muscle">
                Набор мышц
              </option>

              <option value="strength">
                Сила
              </option>

              <option value="fitness">
                Общая форма
              </option>

              <option value="endurance">
                Выносливость
              </option>

            </select>

          </div>


          <div class="ai-field ai-field--full">

            <label for="ai-muscles">
              Какие мышцы хочешь тренировать?
            </label>

            <textarea
              id="ai-muscles"
              placeholder="Например: грудь и трицепс"
            ></textarea>

          </div>

        </div>


        <div
          class="ai-error"
          id="ai-error"
          hidden
        ></div>


        <div class="ai-actions">

          <button
            type="button"
            class="ai-primary"
            id="ai-generate"
          >
            ✨ Создать тренировку
          </button>

        </div>

      </div>


      <div
        class="ai-result"
        id="ai-result"
        hidden
      ></div>


      <div
        class="ai-paywall"
        id="ai-paywall"
        hidden
      >

        <div class="ai-paywall__icon">
          ⭐
        </div>

        <h2 id="ai-paywall-title">
          Free limit reached
        </h2>

        <p id="ai-paywall-text">
          Ты использовал 2 бесплатных
          AI-запроса.
        </p>


        <div class="ai-paywall__price">

          119,99 ₴

          <small>
            / месяц
          </small>

        </div>


        <ul class="ai-pro-list">

          <li>
            ✓ Unlimited AI Assistant
          </li>

          <li>
            ✓ AI Workout Generator
          </li>

          <li>
            ✓ Сохранение AI тренировок
          </li>

          <li>
            ✓ Персональные рекомендации
          </li>

        </ul>


        <div class="ai-actions">

          <button
            type="button"
            class="ai-primary"
            id="ai-buy-pro"
          >
            Купить PRO
          </button>


          <button
            type="button"
            class="ai-secondary"
            id="ai-continue-free"
          >
            Продолжить бесплатно
          </button>

        </div>

      </div>

    </div>
  `;


  document.body.appendChild(
    modal
  );


  const formView =
    document.getElementById(
      'ai-form-view'
    );


  const resultView =
    document.getElementById(
      'ai-result'
    );


  const paywall =
    document.getElementById(
      'ai-paywall'
    );


  const status =
    document.getElementById(
      'ai-request-status'
    );


  const errorBox =
    document.getElementById(
      'ai-error'
    );


  const physical =
    data.physical &&
    typeof data.physical === 'object'
      ? data.physical
      : {};


  document.getElementById(
    'ai-age'
  ).value =
    physical.age || '';


  document.getElementById(
    'ai-height'
  ).value =
    physical.height || '';


  document.getElementById(
    'ai-weight'
  ).value =
    physical.weight || '';


  const savedExperience =
    String(
      physical.experience || ''
    ).toLowerCase();


  if (
    [
      'beginner',
      'intermediate',
      'advanced'
    ].includes(
      savedExperience
    )
  ) {

    document.getElementById(
      'ai-experience'
    ).value =
      savedExperience;
  }


  const MUSCLE_GROUPS = [

    {
      label: 'Chest',

      aliases: [
        'грудь',
        'грудные',
        'chest',
        'pec'
      ],

      muscles: [
        'Chest'
      ]
    },


    {
      label: 'Triceps',

      aliases: [
        'трицепс',
        'трицепсы',
        'triceps'
      ],

      muscles: [
        'Triceps'
      ]
    },


    {
      label: 'Biceps',

      aliases: [
        'бицепс',
        'бицепсы',
        'biceps'
      ],

      muscles: [
        'Biceps'
      ]
    },


    {
      label: 'Back',

      aliases: [
        'спина',
        'широчайшие',
        'back',
        'lats'
      ],

      muscles: [
        'Back',
        'Lats',
        'Trapezius',
        'Lower Back'
      ]
    },


    {
      label: 'Shoulders',

      aliases: [
        'плечи',
        'плечо',
        'дельты',
        'shoulders',
        'delts'
      ],

      muscles: [
        'Shoulders',
        'Front Deltoid',
        'Lateral Deltoid',
        'Rear Deltoid'
      ]
    },


    {
      label: 'Legs',

      aliases: [
        'ноги',
        'квадрицепс',
        'бедра',
        'legs',
        'quads'
      ],

      muscles: [
        'Quadriceps',
        'Hamstrings',
        'Glutes',
        'Adductors',
        'Calves'
      ]
    },


    {
      label: 'Glutes',

      aliases: [
        'ягодицы',
        'ягодичные',
        'glutes'
      ],

      muscles: [
        'Glutes'
      ]
    },


    {
      label: 'Core',

      aliases: [
        'пресс',
        'кор',
        'живот',
        'abs',
        'core'
      ],

      muscles: [
        'Core',
        'Obliques'
      ]
    },


    {
      label: 'Forearms',

      aliases: [
        'предплечья',
        'forearms'
      ],

      muscles: [
        'Forearms',
        'Forearm Flexors'
      ]
    }

  ];


  function detectMuscleGroups(
    text
  ) {

    const value =
      text
        .toLowerCase()
        .trim();


    return MUSCLE_GROUPS.filter(
      group =>

        group.aliases.some(
          alias =>
            value.includes(alias)
        )

    );
  }


  function getPrescription(
    goal,
    experience
  ) {

    if (goal === 'strength') {

      return {
        sets:
          experience === 'beginner'
            ? 3
            : 4,

        reps: 6
      };
    }


    if (goal === 'endurance') {

      return {
        sets: 3,
        reps: 15
      };
    }


    if (goal === 'muscle') {

      return {
        sets:
          experience === 'advanced'
            ? 4
            : 3,

        reps: 10
      };
    }


    return {
      sets: 3,
      reps: 12
    };
  }


  function selectExercises(
    groups
  ) {

    const selected = [];

    const selectedIds =
      new Set();


    groups.forEach(
      group => {

        const candidates =
          EXERCISE_LIBRARY.filter(
            exercise =>

              exercise.muscles.some(
                muscle =>
                  group.muscles.includes(
                    muscle
                  )
              )

          );


        candidates
          .slice(0, 3)
          .forEach(
            exercise => {

              if (
                selectedIds.has(
                  exercise.id
                )
              ) {
                return;
              }


              selectedIds.add(
                exercise.id
              );


              selected.push(
                exercise
              );

            }
          );

      }
    );


    const maximum =
      groups.length === 1
        ? 5
        : 6;


    return selected.slice(
      0,
      maximum
    );
  }


  function updateStatus() {

    resetWindowIfNeeded();


    if (isPro()) {

      status.classList.add(
        'is-pro'
      );


      const date =
        new Date(
          subscriptionEndTime()
        );


      status.textContent =
        '⭐ PRO активен до ' +
        date.toLocaleDateString();


      return;
    }


    status.classList.remove(
      'is-pro'
    );


    status.textContent =
      `Бесплатно: ${
        remainingRequests()
      } / ${FREE_LIMIT} • ` +
      `сброс через ${
        remainingWindowText()
      }`;
  }


  function hideError() {

    errorBox.hidden =
      true;


    errorBox.textContent =
      '';
  }


  function showError(
    message
  ) {

    errorBox.textContent =
      message;


    errorBox.hidden =
      false;
  }


  function showForm() {

    paywall.hidden =
      true;


    formView.hidden =
      false;


    updateStatus();
  }


  function showPaywall(
    expired = false
  ) {

    formView.hidden =
      true;


    resultView.hidden =
      true;


    paywall.hidden =
      false;


    document.getElementById(
      'ai-paywall-title'
    ).textContent =
      expired
        ? 'PRO закончился'
        : 'Free limit reached';


    document.getElementById(
      'ai-paywall-text'
    ).textContent =
      expired

        ? 'Срок PRO закончился. Продли подписку, чтобы снова использовать AI без ограничений.'

        : 'Ты использовал 2 бесплатных AI-запроса. Бесплатный лимит восстановится через 12 часов.';
  }


  function openAssistant() {

    modal.hidden =
      false;


    document.body.style.overflow =
      'hidden';


    hideError();


    if (
      !isPro() &&
      remainingRequests() <= 0
    ) {

      showPaywall(false);

    } else {

      showForm();
    }
  }


  function closeAssistant() {

    modal.hidden =
      true;


    document.body.style.overflow =
      '';
  }


  toggle.addEventListener(
    'click',
    openAssistant
  );


  document.getElementById(
    'ai-assistant-close'
  ).addEventListener(
    'click',
    closeAssistant
  );


  modal.addEventListener(
    'click',
    event => {

      if (
        event.target === modal
      ) {

        closeAssistant();
      }

    }
  );


  document.getElementById(
    'ai-buy-pro'
  ).addEventListener(
    'click',
    () => {

      location.href =
        'payment.html';
    }
  );


  document.getElementById(
    'ai-continue-free'
  ).addEventListener(
    'click',
    () => {

      showForm();
    }
  );


  document.getElementById(
    'ai-generate'
  ).addEventListener(
    'click',
    () => {

      hideError();


      resetWindowIfNeeded();


      if (
        !isPro() &&
        remainingRequests() <= 0
      ) {

        showPaywall(false);

        return;
      }


      const age =
        Number(
          document.getElementById(
            'ai-age'
          ).value
        );


      const height =
        Number(
          document.getElementById(
            'ai-height'
          ).value
        );


      const weight =
        Number(
          document.getElementById(
            'ai-weight'
          ).value
        );


      const experience =
        document.getElementById(
          'ai-experience'
        ).value;


      const goal =
        document.getElementById(
          'ai-goal'
        ).value;


      const musclesText =
        document.getElementById(
          'ai-muscles'
        ).value.trim();


      if (
        !age ||
        age < 10 ||
        age > 100
      ) {

        showError(
          'Укажи корректный возраст.'
        );

        return;
      }


      if (
        !height ||
        height < 100 ||
        height > 250
      ) {

        showError(
          'Укажи корректный рост.'
        );

        return;
      }


      if (
        !weight ||
        weight < 30 ||
        weight > 300
      ) {

        showError(
          'Укажи корректный вес.'
        );

        return;
      }


      if (!musclesText) {

        showError(
          'Напиши, какие мышцы хочешь тренировать.'
        );

        return;
      }


      const groups =
        detectMuscleGroups(
          musclesText
        );


      if (
        groups.length === 0
      ) {

        showError(
          'Я не понял мышцы. Например напиши: грудь и трицепс, спина и бицепс, ноги, плечи или пресс.'
        );

        return;
      }


      const selectedExercises =
        selectExercises(
          groups
        );


      if (
        selectedExercises.length === 0
      ) {

        showError(
          'Не удалось подобрать упражнения.'
        );

        return;
      }


      const prescription =
        getPrescription(
          goal,
          experience
        );


      if (!isPro()) {

        aiState.used += 1;

      }


      const title =
        'AI • ' +
        groups
          .map(
            group =>
              group.label
          )
          .join(' + ');


      const exercises =
        selectedExercises.map(
          exercise => ({

            id:
              uid('ex'),

            name:
              exercise.name,

            sets:
              prescription.sets,

            reps:
              prescription.reps,

            weight:
              ''

          })
        );


      const program = {

        id:
          uid('prog'),

        title,

        description:
          `AI workout • ${age} y.o. • ${height} cm • ${weight} kg`,

        difficulty:
          experience,

        equipment:
          'Mixed',

        createdBy:
          'ai-assistant',

        createdAt:
          new Date().toISOString(),

        templates: [

          {

            id:
              uid('tpl'),

            day:
              'Monday',

            exercises

          }

        ]

      };


      data.programs.push(
        program
      );


      const planSaved =
        saveAIData();


      if (!planSaved) {

        data.programs.pop();


        if (!isPro()) {
          aiState.used =
            Math.max(
              0,
              aiState.used - 1
            );
        }


        showError(
          'Не удалось сохранить тренировку. Проверь, разрешено ли браузеру хранить данные.'
        );

        return;
      }


      showAppToast(
        'Ваш план тренировок успешно добавлен во вкладку «Тренировки».',
        {
          type: 'success',
          duration: 4500,
          actionText: 'Открыть',
          onAction: () => {
            location.href =
              'workouts.html';
          }
        }
      );


      updateStatus();


      resultView.hidden =
        false;


      resultView.innerHTML = `

        <h3>
          ${escapeHtml(title)}
        </h3>

        <p>
          Готово. Тренировка уже
          сохранена в Workouts.
        </p>

        <ol class="ai-workout-list">

          ${exercises
            .map(
              exercise => `

                <li>

                  <strong>
                    ${escapeHtml(
                      exercise.name
                    )}
                  </strong>

                  —
                  ${exercise.sets}
                  ×
                  ${exercise.reps}

                </li>

              `
            )
            .join('')}

        </ol>


        <div class="ai-saved">
          ✓ Workout saved
        </div>


        <div class="ai-actions">

          <button
            type="button"
            class="ai-primary"
            id="ai-open-workouts"
          >
            Открыть Workouts
          </button>

          <button
            type="button"
            class="ai-secondary"
            id="ai-create-another"
          >
            Создать ещё
          </button>

        </div>

      `;


      document.getElementById(
        'ai-open-workouts'
      ).addEventListener(
        'click',
        () => {

          location.href =
            'workouts.html';

        }
      );


      document.getElementById(
        'ai-create-another'
      ).addEventListener(
        'click',
        () => {

          resultView.hidden =
            true;


          if (
            !isPro() &&
            remainingRequests() <= 0
          ) {

            showPaywall(false);

          }

        }
      );

    }
  );


  /* -----------------------------------------
     PRO expired notification
     ----------------------------------------- */

  const expiration =
    subscriptionEndTime();


  if (
    aiState.subscriptionUntil &&
    expiration > 0 &&
    expiration <= Date.now() &&
    aiState.expiredNoticeFor !==
      aiState.subscriptionUntil
  ) {

    aiState.expiredNoticeFor =
      aiState.subscriptionUntil;


    saveAIData();


    setTimeout(
      () => {

        modal.hidden =
          false;


        document.body.style.overflow =
          'hidden';


        showPaywall(true);

      },
      600
    );
  }


  updateStatus();
}
/* =========================================================
   calculator.html — Nutrition AI
   ========================================================= */

function initCalculator() {

  const root =
    document.getElementById(
      'calculator-root'
    );


  if (!root) {
    return;
  }


  const data =
    SF.loadData();


  if (
    !Array.isArray(
      data.nutritionMeals
    )
  ) {
    data.nutritionMeals = [];
  }


  initTopbar(
    Array.isArray(data.workouts)
      ? data.workouts.length
      : 0
  );


  /* =========================================
     LANGUAGE
     ========================================= */

  const lang =
    I18N.getLang();


  document
    .querySelectorAll(
      '[data-calc-en][data-calc-ru]'
    )
    .forEach(el => {

      el.textContent =
        lang === 'ru'
          ? el.dataset.calcRu
          : el.dataset.calcEn;

    });


  document
    .querySelectorAll(
      '[data-calc-ph-en][data-calc-ph-ru]'
    )
    .forEach(el => {

      el.placeholder =
        lang === 'ru'
          ? el.dataset.calcPhRu
          : el.dataset.calcPhEn;

    });



  /* =========================================
     PROFILE PREFILL
     ========================================= */

  const physical =
    data.physical &&
    typeof data.physical === 'object'
      ? data.physical
      : {};


  const sexEl =
    document.getElementById(
      'calc-sex'
    );

  const ageEl =
    document.getElementById(
      'calc-age'
    );

  const heightEl =
    document.getElementById(
      'calc-height'
    );

  const weightEl =
    document.getElementById(
      'calc-weight'
    );


  if (physical.gender) {
    sexEl.value =
      physical.gender;
  }

  if (physical.age) {
    ageEl.value =
      physical.age;
  }

  if (physical.height) {
    heightEl.value =
      physical.height;
  }

  if (physical.weight) {
    weightEl.value =
      physical.weight;
  }



  /* =========================================
     IMAGE UPLOAD
     ========================================= */

  const fileInput =
    document.getElementById(
      'food-photo'
    );

  const drop =
    document.getElementById(
      'food-drop'
    );

  const previewWrap =
    document.getElementById(
      'food-preview-wrap'
    );

  const preview =
    document.getElementById(
      'food-preview'
    );

  const remove =
    document.getElementById(
      'food-remove'
    );

  const analyze =
    document.getElementById(
      'food-analyze'
    );

  const note =
    document.getElementById(
      'food-note'
    );

  const status =
    document.getElementById(
      'food-status'
    );


  let selectedFile =
    null;


  let lastResult =
    null;


  /*
    IMPORTANT:

    When your server gets an HTTPS address,
    replace this URL.

    Example:
    https://api.yoursite.com/api/nutrition/analyze
  */

const NUTRITION_API_URL =
  'https://fitness-nutrition-ai.v4msg6c8t6.workers.dev/api/nutrition/analyze';



  function showStatus(
    message,
    error = false
  ) {

    status.hidden =
      false;

    status.textContent =
      message;

    status.style.color =
      error
        ? 'var(--error)'
        : 'var(--muted)';
  }


  function hideStatus() {

    status.hidden =
      true;

    status.textContent =
      '';
  }


  function clearPhoto() {

    selectedFile =
      null;

    lastResult =
      null;

    fileInput.value =
      '';

    preview.removeAttribute(
      'src'
    );

    previewWrap.hidden =
      true;

    drop.hidden =
      false;

    document.getElementById(
      'food-result'
    ).hidden =
      true;

    hideStatus();
  }


  function setPhoto(
    file
  ) {

    if (!file) {
      return;
    }


    const allowed = [
      'image/jpeg',
      'image/png',
      'image/webp'
    ];


    if (
      !allowed.includes(
        file.type
      )
    ) {

      showStatus(
        lang === 'ru'
          ? 'Поддерживаются JPG, PNG и WEBP.'
          : 'Only JPG, PNG and WEBP are supported.',
        true
      );

      return;
    }


    if (
      file.size >
      10 * 1024 * 1024
    ) {

      showStatus(
        lang === 'ru'
          ? 'Фото слишком большое. Максимум 10 МБ.'
          : 'The image is too large. Maximum size is 10 MB.',
        true
      );

      return;
    }


    selectedFile =
      file;


    const url =
      URL.createObjectURL(
        file
      );


    preview.onload =
      () => {
        URL.revokeObjectURL(
          url
        );
      };


    preview.src =
      url;


    drop.hidden =
      true;

    previewWrap.hidden =
      false;

    hideStatus();
  }


  fileInput.addEventListener(
    'change',
    () => {

      setPhoto(
        fileInput.files[0]
      );

    }
  );


  remove.addEventListener(
    'click',
    clearPhoto
  );



  /* drag & drop desktop */

  [
    'dragenter',
    'dragover'
  ].forEach(
    eventName => {

      drop.addEventListener(
        eventName,
        e => {

          e.preventDefault();

          drop.classList.add(
            'is-dragging'
          );

        }
      );

    }
  );


  [
    'dragleave',
    'drop'
  ].forEach(
    eventName => {

      drop.addEventListener(
        eventName,
        e => {

          e.preventDefault();

          drop.classList.remove(
            'is-dragging'
          );

        }
      );

    }
  );


  drop.addEventListener(
    'drop',
    e => {

      const file =
        e.dataTransfer
          ?.files?.[0];

      if (file) {
        setPhoto(file);
      }

    }
  );



  /* =========================================
     AI RESULT
     ========================================= */

  function renderFoodResult(
    result
  ) {

    lastResult =
      result;


    document.getElementById(
      'food-result-name'
    ).textContent =
      result.dish_name ||
      'Meal';


    document.getElementById(
      'food-confidence'
    ).textContent =
      `${Math.round(
        Number(result.confidence) || 0
      )}%`;


    document.getElementById(
      'food-kcal'
    ).textContent =
      Math.round(
        Number(
          result.calories_kcal
        ) || 0
      );


    document.getElementById(
      'food-protein'
    ).textContent =
      Number(
        result.protein_g || 0
      ).toFixed(1);


    document.getElementById(
      'food-fat'
    ).textContent =
      Number(
        result.fat_g || 0
      ).toFixed(1);


    document.getElementById(
      'food-carbs'
    ).textContent =
      Number(
        result.carbs_g || 0
      ).toFixed(1);


    document.getElementById(
      'food-portion'
    ).textContent =
      `${Math.round(
        Number(
          result.portion_grams
        ) || 0
      )} g`;


    const ingredients =
      document.getElementById(
        'food-ingredients'
      );


    ingredients.innerHTML =
      '';


    (
      result.ingredients || []
    ).forEach(
      item => {

        const pill =
          document.createElement(
            'span'
          );

        pill.className =
          'food-ingredient-pill';


        pill.textContent =
          item.estimated_grams
            ? `${item.name} · ${Math.round(item.estimated_grams)} g`
            : item.name;


        ingredients.appendChild(
          pill
        );

      }
    );


    document.getElementById(
      'food-ai-note'
    ).textContent =
      result.note || '';


    document.getElementById(
      'food-result'
    ).hidden =
      false;

  }



  analyze.addEventListener(
    'click',
    async () => {

      if (!selectedFile) {

        showStatus(
          lang === 'ru'
            ? 'Сначала добавь фотографию блюда.'
            : 'Add a meal photo first.',
          true
        );

        return;
      }



      analyze.disabled =
        true;


      showStatus(
        lang === 'ru'
          ? '✨ AI анализирует блюдо...'
          : '✨ AI is analyzing your meal...'
      );


      try {

        const form =
          new FormData();


        form.append(
          'image',
          selectedFile
        );


        form.append(
          'note',
          note.value.trim()
        );


        form.append(
          'language',
          lang
        );


        const response =
          await fetch(
            NUTRITION_API_URL,
            {
              method: 'POST',
              body: form
            }
          );


        const responseText =
          await response.text();


        let result =
          null;


        try {

          result =
            responseText
              ? JSON.parse(responseText)
              : {};

        } catch {

          throw new Error(
            response.ok
              ? 'Сервер вернул некорректный ответ.'
              : `HTTP ${response.status}: ${responseText.slice(0, 180) || 'Server error'}`
          );

        }


        if (
          !response.ok
        ) {

          throw new Error(
            result.error ||
            `HTTP ${response.status}: AI analysis failed.`
          );

        }


        const requiredFields = [
          'dish_name',
          'portion_grams',
          'calories_kcal',
          'protein_g',
          'fat_g',
          'carbs_g',
          'confidence',
          'ingredients',
          'note'
        ];


        const missingField =
          requiredFields.find(
            key =>
              !Object.prototype.hasOwnProperty.call(
                result,
                key
              )
          );


        if (missingField) {

          throw new Error(
            `AI returned an incomplete result: ${missingField}`
          );

        }


        renderFoodResult(
          result
        );


        hideStatus();


      } catch (error) {

        console.error(
          'Nutrition AI error:',
          error
        );


        const message =
          error &&
          error.message
            ? error.message
            : 'Unknown error';


        showStatus(
          lang === 'ru'
            ? `Ошибка AI: ${message}`
            : `AI error: ${message}`,
          true
        );


      } finally {

        analyze.disabled =
          false;

      }

    }
  );



  /* =========================================
     SAVE MEAL
     ========================================= */

  document.getElementById(
    'save-meal'
  ).addEventListener(
    'click',
    () => {

      if (!lastResult) {
        return;
      }


      data.nutritionMeals.unshift({

        id:
          'meal_' +
          Date.now(),

        createdAt:
          new Date()
            .toISOString(),

        ...lastResult

      });


      data.nutritionMeals =
        data.nutritionMeals
          .slice(
            0,
            30
          );


      const mealSaved =
        SF.saveData(
          data
        );


      if (!mealSaved) {

        data.nutritionMeals.shift();

        showStatus(
          lang === 'ru'
            ? 'Не удалось сохранить приём пищи в браузере.'
            : 'Could not save the meal in browser storage.',
          true
        );

        return;
      }


      renderHistory();


      if (
        typeof showAppToast ===
        'function'
      ) {

        showAppToast(
          lang === 'ru'
            ? 'Приём пищи сохранён.'
            : 'Meal saved.',
          {
            type: 'success'
          }
        );

      } else {

        showStatus(
          lang === 'ru'
            ? '✓ Приём пищи сохранён.'
            : '✓ Meal saved.'
        );

      }

    }
  );



  /* =========================================
     HISTORY
     ========================================= */

  function renderHistory() {

    const container =
      document.getElementById(
        'nutrition-history'
      );


    if (
      data.nutritionMeals.length === 0
    ) {

      container.innerHTML =
        `
          <div class="empty-state">

            <div class="empty-state__icon">
              🥗
            </div>

            <p class="empty-state__title">
              ${
                lang === 'ru'
                  ? 'Пока ничего не сохранено'
                  : 'No saved meals yet'
              }
            </p>

            <p class="empty-state__sub">
              ${
                lang === 'ru'
                  ? 'Проанализируй блюдо и сохрани его.'
                  : 'Analyze a meal and save it here.'
              }
            </p>

          </div>
        `;

      return;
    }


    container.innerHTML =
      data.nutritionMeals
        .slice(0, 8)
        .map(
          meal => {

            const date =
              new Date(
                meal.createdAt
              );


            return `
              <div class="nutrition-meal-row">

                <div>

                  <div class="nutrition-meal-name">
                    ${escapeNutritionHtml(
                      meal.dish_name ||
                      'Meal'
                    )}
                  </div>

                  <div class="nutrition-meal-meta">

                    ${date.toLocaleString()}

                    · P ${Number(meal.protein_g || 0).toFixed(1)}

                    · F ${Number(meal.fat_g || 0).toFixed(1)}

                    · C ${Number(meal.carbs_g || 0).toFixed(1)}

                  </div>

                </div>


                <div class="nutrition-meal-kcal">

                  ${Math.round(
                    meal.calories_kcal || 0
                  )} kcal

                </div>

              </div>
            `;

          }
        )
        .join('');

  }


  function escapeNutritionHtml(
    value
  ) {

    return String(
      value
    ).replace(
      /[&<>"']/g,
      char => ({

        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'

      })[char]
    );

  }



  /* =========================================
     CALORIE CALCULATOR
     Mifflin-St Jeor — adults
     ========================================= */

  document.getElementById(
    'calorie-form'
  ).addEventListener(
    'submit',
    e => {

      e.preventDefault();


      const sex =
        sexEl.value;


      const age =
        Number(
          ageEl.value
        );


      const height =
        Number(
          heightEl.value
        );


      const weight =
        Number(
          weightEl.value
        );


      const activity =
        Number(
          document.getElementById(
            'calc-activity'
          ).value
        );


      const goal =
        document.getElementById(
          'calc-goal'
        ).value;


      const warning =
        document.getElementById(
          'calorie-warning'
        );


      const result =
        document.getElementById(
          'calorie-result'
        );


      warning.hidden =
        true;


      result.hidden =
        true;


      if (
        !sex ||
        !age ||
        !height ||
        !weight
      ) {

        warning.textContent =
          lang === 'ru'
            ? 'Заполни все поля.'
            : 'Complete all fields.';

        warning.hidden =
          false;

        return;
      }


      /*
        Adult calculator only.
        For minors, adult deficit/surplus formulas
        should not be used.
      */

      if (
        age < 18
      ) {

        warning.textContent =
          lang === 'ru'
            ? 'Для возраста младше 18 лет взрослые формулы похудения и набора использовать некорректно. Для подростков потребности зависят от возраста и развития — лучше использовать расчёт специалиста.'
            : 'Adult weight-loss and gain formulas are not appropriate for people under 18. Energy needs during growth require age-specific guidance.';

        warning.hidden =
          false;

        return;
      }


      let bmr =
        10 * weight +
        6.25 * height -
        5 * age;


      bmr +=
        sex === 'male'
          ? 5
          : -161;


      const maintenance =
        bmr *
        activity;


      let target =
        maintenance;


      if (
        goal === 'lose'
      ) {

        target =
          maintenance *
          0.85;

      }


      if (
        goal === 'gain'
      ) {

        target =
          maintenance *
          1.10;

      }


      document.getElementById(
        'calc-bmr'
      ).textContent =
        Math.round(
          bmr
        ) +
        ' kcal';


      document.getElementById(
        'calc-maintenance'
      ).textContent =
        Math.round(
          maintenance
        ) +
        ' kcal';


      document.getElementById(
        'target-calories'
      ).textContent =
        Math.round(
          target
        );


      const noteEl =
        document.getElementById(
          'calorie-result-note'
        );


      if (
        lang === 'ru'
      ) {

        noteEl.textContent =
          goal === 'lose'
            ? 'Использован умеренный дефицит около 15%. Это приблизительная оценка, а не медицинская рекомендация.'
            : goal === 'gain'
              ? 'Использован умеренный профицит около 10%. Корректируй питание по динамике веса и тренировок.'
              : 'Это приблизительная оценка калорий для поддержания текущего веса.';

      } else {

        noteEl.textContent =
          goal === 'lose'
            ? 'Uses an estimated 15% calorie deficit. This is an estimate, not medical advice.'
            : goal === 'gain'
              ? 'Uses an estimated 10% calorie surplus. Adjust according to weight and training trends.'
              : 'Estimated calories for maintaining current body weight.';

      }


      result.hidden =
        false;

    }
  );


  renderHistory();

}
/* ---------- start ---------- */
SF.guard();
SF.initTheme();
I18N.applyStatic();
I18N.initToggle();

initSignin();
initSignup();

initAnatomicalMuscleMap();

initHome();
initWorkouts();
initCalendar();
initExerciseLibrary();

initCalculator();

initAIAssistant();

if (
  window.Telegram &&
  window.Telegram.WebApp
) {
  window.Telegram.WebApp.expand();
}