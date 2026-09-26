'use strict';

const SF = (() => {
  const KEYS = { users: 'sf_users', session: 'sf_session', theme: 'sf_theme' };
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  const MIN_PASSWORD = 8;

  const read = (key, fallback) => {
    try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : fallback; }
    catch { return fallback; }
  };
  const write = (key, value) => {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; }
    catch { return false; }
  };

  const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
  const isValidEmail = (email) => EMAIL_RE.test(normalizeEmail(email));

  const getUsers = () => read(KEYS.users, []);

  async function login(email, password) {
    email = normalizeEmail(email);
    const genericError = { ok: false, error: 'Неверный email или пароль.' };
    const user = getUsers().find(u => u.email === email);
    
    if (!user) return genericError;

    // В учебных целях / без сервера проверяем простой пароль или сохранённый хэш
    if (user.password && user.password !== password) return genericError;

    const session = { id: user.id, email: user.email, name: user.name || user.email.split('@')[0] };
    if (!write(KEYS.session, session)) return { ok: false, error: 'Не удалось сохранить сессию.' };
    return { ok: true, user: session };
  }

  function currentUser() {
    return read(KEYS.session, null);
  }

  function logout() {
    try { localStorage.removeItem(KEYS.session); } catch {}
    location.replace('index.html');
  }

  function guard() {
    const mode = document.body.dataset.auth;
    const user = currentUser();
    
    if (mode === 'guest' && user) {
      location.replace('home.html');
    } else if (mode === 'required' && !user) {
      location.replace('index.html');
    }
  }

  const ICONS = {
    dark:  { src: 'Sun.jpeg', alt: 'Sun',  label: 'Переключить на светлую тему' },
    light: { src: 'dark.png', alt: 'Moon', label: 'Переключить на тёмную тему' }
  };

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(KEYS.theme, theme); } catch {}
    const btn = document.getElementById('theme-toggle');
    const img = document.getElementById('theme-toggle-img');
    if (!btn || !img) return;
    img.src = ICONS[theme].src;
    img.alt = ICONS[theme].alt;
  }

  function initTheme() {
    const currentTheme = document.documentElement.dataset.theme || 'dark';
    applyTheme(currentTheme);
    const btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.addEventListener('click', () => {
        const nextTheme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
        applyTheme(nextTheme);
      });
    }
  }

  return { login, logout, currentUser, guard, initTheme, isValidEmail };
})();

// Авторизация на странице Sign In
function initSignin() {
  const form = document.getElementById('signin-form');
  if (!form) return;

  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const emailErr = document.getElementById('email-error');
  const passErr = document.getElementById('password-error');
  const message = document.getElementById('form-message');
  const button = document.getElementById('signin-btn');

  const setMessage = (text) => { if(message) message.textContent = text; };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    setMessage('');

    let valid = true;
    if (!SF.isValidEmail(email.value)) { 
      if(emailErr) emailErr.textContent = 'Введите корректный email.'; 
      valid = false; 
    }
    if (!password.value) { 
      if(passErr) passErr.textContent = 'Введите пароль.'; 
      valid = false; 
    }
    if (!valid) return;

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

// Страница Личного кабинета (Home)
function initHome() {
  const user = SF.currentUser();
  const userNameElem = document.getElementById('user-display-name');
  const logoutBtn = document.getElementById('logout-btn');

  if (userNameElem && user) {
    userNameElem.textContent = user.name || user.email;
  }
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => SF.logout());
  }
}

// Запуск инициализации при загрузке
document.addEventListener('DOMContentLoaded', () => {
  SF.guard();
  SF.initTheme();

  const page = document.body.dataset.page;
  if (page === 'signin') initSignin();
  if (page === 'home') initHome();
});