/* ============================================================================
   APP — Main Router & Navigation Controller
   ============================================================================ */

const App = (() => {
  const appContainer = document.getElementById('app');

  // ── Route definitions ─────────────────────────────────────────
  const PUBLIC_ROUTES = ['#/login', '#/signup'];

  function getRoute() {
    return window.location.hash || '#/login';
  }

  // ── Navigation rendering ──────────────────────────────────────
  function updateNav() {
    const nav = document.getElementById('mainNav');
    const navLinks = document.getElementById('navLinks');
    const navUser = document.getElementById('navUser');

    if (!Auth.isLoggedIn()) {
      nav.classList.add('hidden');
      return;
    }

    nav.classList.remove('hidden');

    // Highlight active link
    const route = getRoute();
    document.querySelectorAll('.nav-link[data-route]').forEach(link => {
      if (link.getAttribute('data-route') === route) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Show user email
    document.getElementById('navEmailText').textContent = Auth.getEmail() || '';
  }

  // ── Router ────────────────────────────────────────────────────
  function route() {
    const hash = getRoute();

    // Auth guard — if not logged in and not on a public route
    if (!Auth.isLoggedIn() && !PUBLIC_ROUTES.includes(hash)) {
      window.location.hash = '#/login';
      return;
    }

    // If logged in and on a public route, redirect to scan
    if (Auth.isLoggedIn() && PUBLIC_ROUTES.includes(hash)) {
      window.location.hash = '#/scan';
      return;
    }

    updateNav();

    // Cleanup previous page
    if (typeof Scanner !== 'undefined') Scanner.cleanup();

    // Route matching
    if (hash === '#/login') {
      Auth.renderLogin(appContainer);
    } else if (hash === '#/signup') {
      Auth.renderSignup(appContainer);
    } else if (hash === '#/scan') {
      Scanner.render(appContainer);
    } else if (hash === '#/history') {
      History.render(appContainer);
    } else if (hash.startsWith('#/report/')) {
      const scanId = hash.replace('#/report/', '');
      Report.render(appContainer, scanId);
    } else {
      // Default
      window.location.hash = Auth.isLoggedIn() ? '#/scan' : '#/login';
    }
  }

  // ── Initialize ────────────────────────────────────────────────
  function init() {
    // Nav link click handlers
    document.querySelectorAll('.nav-link[data-route]').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.hash = link.getAttribute('data-route');
      });
    });

    // Logout button
    document.getElementById('logoutBtn').addEventListener('click', () => {
      Auth.logout();
    });

    // Hash change listener
    window.addEventListener('hashchange', route);

    // Initial route
    route();
  }

  return { init };
})();

// Boot the app when DOM is ready
document.addEventListener('DOMContentLoaded', App.init);
