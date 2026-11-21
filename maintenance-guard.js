(() => {
  const path = window.location.pathname;
  if (path === '/maintenance.html' || path === '/admin' || path === '/admin/' || path === '/admin.html' || path.startsWith('/admin/')) return;

  fetch('https://api.nukavsevmeste.org/api/site-status', {
    method: 'GET',
    cache: 'no-store',
    credentials: 'omit',
    headers: { Accept: 'application/json' }
  })
    .then(response => {
      if (!response.ok) throw new Error('Не удалось проверить доступность сайта');
      return response.json();
    })
    .then(status => {
      if (status && status.maintenance === true) {
        window.location.replace('/maintenance.html');
      }
    })
    .catch(() => {
      // Если API временно недоступен, не блокируем обычную работу сайта.
    });
})();
