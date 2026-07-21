// Shared auth: nav pill, login/signup modal. Included by index.html and
// marketplace.html so session state (cookie-based) looks the same everywhere.
const Auth = (() => {
  let currentUser = null;
  let onChangeCb = null;

  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  function injectModal() {
    const div = document.createElement('div');
    div.innerHTML = `
      <div class="modal-backdrop" id="authBackdrop">
        <div class="modal" style="position:relative">
          <button class="ghost sm" id="authClose" style="position:absolute;top:14px;right:14px;padding:4px 10px">✕</button>
          <h2 id="authTitle">Sign in</h2>
          <div id="authError" class="field-error"></div>
          <form id="authForm">
            <div id="authNameField" style="display:none">
              <label>Display name</label>
              <input type="text" id="authName" autocomplete="name">
            </div>
            <label>Email</label>
            <input type="email" id="authEmail" autocomplete="email" required style="width:100%">
            <label>Password</label>
            <input type="password" id="authPassword" autocomplete="current-password" required style="width:100%" minlength="8">
            <button type="submit" style="width:100%;margin-top:16px" id="authSubmit">Sign in</button>
          </form>
          <p class="switch">
            <span id="authSwitchPrompt">No account?</span>
            <a href="#" id="authSwitchLink">Sign up</a>
          </p>
        </div>
      </div>`;
    document.body.appendChild(div);

    let mode = 'login';
    const setMode = m => {
      mode = m;
      document.getElementById('authTitle').textContent = m === 'login' ? 'Sign in' : 'Create an account';
      document.getElementById('authNameField').style.display = m === 'login' ? 'none' : 'block';
      document.getElementById('authName').required = m === 'signup';
      document.getElementById('authSubmit').textContent = m === 'login' ? 'Sign in' : 'Sign up';
      document.getElementById('authSwitchPrompt').textContent = m === 'login' ? 'No account?' : 'Already have one?';
      document.getElementById('authSwitchLink').textContent = m === 'login' ? 'Sign up' : 'Sign in';
      document.getElementById('authError').style.display = 'none';
      document.getElementById('authPassword').autocomplete = m === 'login' ? 'current-password' : 'new-password';
    };

    document.getElementById('authSwitchLink').addEventListener('click', e => {
      e.preventDefault(); setMode(mode === 'login' ? 'signup' : 'login');
    });
    document.getElementById('authClose').addEventListener('click', () => close());
    document.getElementById('authBackdrop').addEventListener('click', e => {
      if (e.target.id === 'authBackdrop') close();
    });
    document.getElementById('authForm').addEventListener('submit', async e => {
      e.preventDefault();
      const email = document.getElementById('authEmail').value.trim();
      const password = document.getElementById('authPassword').value;
      const name = document.getElementById('authName').value.trim();
      const errBox = document.getElementById('authError');
      errBox.style.display = 'none';
      try {
        const path = mode === 'login' ? '/api/auth/login' : '/api/auth/signup';
        const body = mode === 'login' ? { email, password } : { email, password, display_name: name };
        const resp = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Something went wrong');
        close();
        await refresh();
        renderNav();
        if (onChangeCb) onChangeCb(currentUser);
      } catch (err) {
        errBox.textContent = err.message;
        errBox.style.display = 'block';
      }
    });

    window.__authSetMode = setMode;
  }

  function open(mode) {
    if (!document.getElementById('authBackdrop')) injectModal();
    window.__authSetMode(mode || 'login');
    document.getElementById('authForm').reset();
    document.getElementById('authBackdrop').classList.add('open');
  }
  function close() {
    const b = document.getElementById('authBackdrop');
    if (b) b.classList.remove('open');
  }

  async function refresh() {
    const resp = await fetch('/api/auth/me');
    const data = await resp.json();
    currentUser = data.user;
    return currentUser;
  }

  async function logout() {
    await fetch('/api/auth/logout', { method: 'POST' });
    currentUser = null;
    if (onChangeCb) onChangeCb(null);
    renderNav();
  }

  function renderNav() {
    const el = document.getElementById('navAuth');
    if (!el) return;
    if (currentUser) {
      el.innerHTML = `<span>${esc(currentUser.display_name)}${currentUser.verified ? ' <span class=\"badge-verified\">✓ verified</span>' : ''}</span>
        <a href="/marketplace#dashboard">Dashboard</a>
        <button class="ghost sm" id="navLogout">Sign out</button>`;
      document.getElementById('navLogout').addEventListener('click', logout);
    } else {
      el.innerHTML = `<button class="ghost sm" id="navSignin">Sign in</button>
        <button class="sm" id="navSignup">Sign up</button>`;
      document.getElementById('navSignin').addEventListener('click', () => open('login'));
      document.getElementById('navSignup').addEventListener('click', () => open('signup'));
    }
  }

  async function init(onChange) {
    onChangeCb = onChange || null;
    await refresh();
    renderNav();
    if (onChangeCb) onChangeCb(currentUser);
    return currentUser;
  }

  return { init, open, close, logout, refresh, get user() { return currentUser; } };
})();
