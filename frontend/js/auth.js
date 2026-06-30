/* ============================================================================
   AUTH MODULE — Login, Sign-up, Token Management
   ============================================================================ */

const Auth = (() => {
  const TOKEN_KEY = 'vulnera_token';
  const EMAIL_KEY = 'vulnera_email';

  // ── Token helpers ─────────────────────────────────────────────
  function saveSession(data) {
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(EMAIL_KEY, data.email);
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(EMAIL_KEY);
  }

  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function getEmail() {
    return localStorage.getItem(EMAIL_KEY);
  }

  function isLoggedIn() {
    return !!getToken();
  }

  function authHeaders() {
    const token = getToken();
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  }

  // ── API calls ─────────────────────────────────────────────────
  async function apiRegister(email, password) {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Registration failed');
    return data;
  }

  async function apiLogin(email, password) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Login failed');
    return data;
  }

  function logout() {
    clearSession();
    window.location.hash = '#/login';
  }

  // ── Render Login Page ─────────────────────────────────────────
  function renderLogin(container) {
    container.innerHTML = `
      <div class="auth-wrapper">
        <div class="auth-card card">
          <div class="auth-header">
            <h1>Welcome Back</h1>
            <p>Sign in to your Vulnera account</p>
          </div>
          <div id="auth-alert"></div>
          <form id="loginForm">
            <div class="form-group">
              <label class="form-label" for="login-email">Email</label>
              <input class="form-input" type="email" id="login-email" placeholder="you@example.com" required autocomplete="email">
            </div>
            <div class="form-group">
              <label class="form-label" for="login-password">Password</label>
              <input class="form-input" type="password" id="login-password" placeholder="••••••••" required autocomplete="current-password">
            </div>
            <button class="btn btn-primary" type="submit" id="login-btn">Sign In</button>
          </form>
          <div class="auth-footer">
            Don't have an account? <a onclick="window.location.hash='#/signup'">Create one</a>
          </div>
        </div>
      </div>
    `;

    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('login-btn');
      const alertBox = document.getElementById('auth-alert');
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;

      btn.disabled = true;
      btn.textContent = 'Signing in...';
      alertBox.innerHTML = '';

      try {
        const data = await apiLogin(email, password);
        saveSession(data);
        window.location.hash = '#/scan';
      } catch (err) {
        alertBox.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
        btn.disabled = false;
        btn.textContent = 'Sign In';
      }
    });
  }

  // ── Render Signup Page ────────────────────────────────────────
  function renderSignup(container) {
    container.innerHTML = `
      <div class="auth-wrapper">
        <div class="auth-card card">
          <div class="auth-header">
            <h1>Create Account</h1>
            <p>Get started with Vulnera scanner</p>
          </div>
          <div id="auth-alert"></div>
          <form id="signupForm">
            <div class="form-group">
              <label class="form-label" for="signup-email">Email</label>
              <input class="form-input" type="email" id="signup-email" placeholder="you@example.com" required autocomplete="email">
            </div>
            <div class="form-group">
              <label class="form-label" for="signup-password">Password</label>
              <input class="form-input" type="password" id="signup-password" placeholder="Min. 6 characters" required minlength="6" autocomplete="new-password">
            </div>
            <div class="form-group">
              <label class="form-label" for="signup-confirm">Confirm Password</label>
              <input class="form-input" type="password" id="signup-confirm" placeholder="••••••••" required minlength="6" autocomplete="new-password">
            </div>
            <button class="btn btn-primary" type="submit" id="signup-btn">Create Account</button>
          </form>
          <div class="auth-footer">
            Already have an account? <a onclick="window.location.hash='#/login'">Sign in</a>
          </div>
        </div>
      </div>
    `;

    document.getElementById('signupForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('signup-btn');
      const alertBox = document.getElementById('auth-alert');
      const email = document.getElementById('signup-email').value.trim();
      const password = document.getElementById('signup-password').value;
      const confirm = document.getElementById('signup-confirm').value;

      alertBox.innerHTML = '';

      if (password !== confirm) {
        alertBox.innerHTML = `<div class="alert alert-error">Passwords do not match</div>`;
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Creating account...';

      try {
        const data = await apiRegister(email, password);
        saveSession(data);
        window.location.hash = '#/scan';
      } catch (err) {
        alertBox.innerHTML = `<div class="alert alert-error">${err.message}</div>`;
        btn.disabled = false;
        btn.textContent = 'Create Account';
      }
    });
  }

  // ── Public API ────────────────────────────────────────────────
  return {
    getToken,
    getEmail,
    isLoggedIn,
    authHeaders,
    logout,
    renderLogin,
    renderSignup,
  };
})();
