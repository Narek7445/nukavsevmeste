(() => {
  const path = window.location.pathname;
  if (path === '/maintenance.html' || path === '/admin' || path === '/admin/' || path === '/admin.html' || path.startsWith('/admin/')) return;

  const check = async () => {
    try {
      const response = await fetch('https://api.nukavsevmeste.org/api/site-status', {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: { Accept: 'application/json' }
      });
      if (!response.ok) return;
      const status = await response.json();
      if (status && status.maintenance === true) {
        window.location.replace('/maintenance.html');
      }
    } catch {
      // При временной недоступности API обычная работа сайта продолжается.
    }
  };

  check();
  setInterval(check, 30000);
})();
