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

  /* ---------- per-user saved data (workout programs etc.) ---------- */
  const loadData = () => { const u = currentUser(); return u ? read('sf_data_' + u.id, {}) : {}; };
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

/* ---------- start ---------- */
SF.guard();
SF.initTheme();
initSignin();
initSignup();