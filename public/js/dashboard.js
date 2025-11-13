// SECURITY: CSRF token management
let csrfToken = null;

async function fetchCsrfToken() {
  try {
    const response = await fetch('/api/csrf-token', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      console.error('Failed to fetch CSRF token');
      return null;
    }

    const data = await response.json();
    csrfToken = data.token;
    return csrfToken;
  } catch (err) {
    console.error('CSRF token fetch error:', err);
    return null;
  }
}

async function authenticatedFetch(url, options = {}) {
  if (options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
    if (!csrfToken) {
      await fetchCsrfToken();
    }

    options.headers = {
      ...options.headers,
      'x-csrf-token': csrfToken
    };
  }

  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options
  });

  if (response.status === 403) {
    console.log('CSRF token expired, refreshing...');
    await fetchCsrfToken();

    if (options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
      options.headers = {
        ...options.headers,
        'x-csrf-token': csrfToken
      };
    }

    return fetch(url, { credentials: 'same-origin', ...options });
  }

  return response;
}

// Hardcoded services as fallback
const FALLBACK_SERVICES = {
  contentManagement: [
    {
      name: 'Sonarr',
      path: '/sonarr',
      icon: 'https://raw.githubusercontent.com/Sonarr/Sonarr/develop/Logo/128.png'
    },
    {
      name: 'Sonarr Anime',
      path: '/anime',
      icon: 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sonarr.png'
    },
    {
      name: 'Radarr',
      path: '/radarr',
      icon: 'https://raw.githubusercontent.com/Radarr/Radarr/develop/Logo/128.png'
    },
    {
      name: 'Lidarr',
      path: '/lidarr',
      icon: 'https://raw.githubusercontent.com/Lidarr/Lidarr/develop/Logo/128.png'
    },
    {
      name: 'Prowlarr',
      path: '/prowlarr',
      icon: 'https://raw.githubusercontent.com/Prowlarr/Prowlarr/develop/Logo/128.png'
    }
  ],
  downloadClients: [
    {
      name: 'qBittorrent',
      path: '/qbit/',
      icon: 'https://raw.githubusercontent.com/qbittorrent/qBittorrent/master/src/icons/qbittorrent-tray.svg'
    },
    {
      name: 'SABnzbd',
      path: '/sab',
      icon: 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/sabnzbd.png'
    }
  ],
  managementAnalytics: [
    {
      name: 'Tautulli',
      path: '/tautulli',
      icon: 'https://raw.githubusercontent.com/Tautulli/Tautulli/master/data/interfaces/default/images/logo.png'
    },
    {
      name: 'Plex',
      path: 'https://plex.cirrolink.com',
      icon: 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/plex.png'
    }
  ]
};

// Current services (will be loaded from API or fallback)
let SERVICES = FALLBACK_SERVICES;

// Category icon SVG paths
function getCategoryIconSVG(iconName, color = '#58a6ff') {
  const icons = {
    film: '<path d="M19.82 2H4.18C2.97 2 2 2.97 2 4.18v15.64C2 21.03 2.97 22 4.18 22h15.64c1.21 0 2.18-.97 2.18-2.18V4.18C22 2.97 21.03 2 19.82 2zM7 2v20M17 2v20M2 12h20M2 7h5M2 17h5M17 7h5M17 17h5"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    chart: '<path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/>',
    folder: '<path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>',
    server: '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    music: '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
    book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    tv: '<rect x="2" y="7" width="20" height="15" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/>'
  };

  const path = icons[iconName] || icons.folder;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 20px; height: 20px; margin-right: 8px; vertical-align: middle;">${path}</svg>`;
}

async function checkAuth() {
  try {
    const response = await fetch('/api/verify', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      window.location.href = '/login';
      return false;
    }

    const data = await response.json();
    if (data.authenticated) {
      document.getElementById('username').textContent = data.displayName || data.username;

      // Show "Manage Users" link for admin users
      if (data.role && ['super_admin', 'admin'].includes(data.role)) {
        const manageUsersLink = document.getElementById('manageUsersLink');
        if (manageUsersLink) {
          manageUsersLink.style.display = 'flex';
        }
      }

      return true;
    } else {
      window.location.href = '/login';
      return false;
    }
  } catch (err) {
    console.error('Auth check failed:', err);
    window.location.href = '/login';
    return false;
  }
}

async function loadServicesFromAPI() {
  try {
    const response = await fetch('/api/dashboard/categories', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      console.warn('Failed to load categories from API, using fallback');
      return false;
    }

    const categoriesData = await response.json();
    SERVICES = categoriesData;
    console.log('Categories and services loaded from API');
    return true;
  } catch (err) {
    console.warn('Failed to load categories from API, using fallback:', err);
    return false;
  }
}

function createServiceCard(service, status = 'loading', activity = null, activityType = 'idle') {
  const card = document.createElement('a');
  card.href = service.path;
  card.className = `service-card ${status}`;
  card.setAttribute('data-path', service.path);
  card.setAttribute('target', '_blank');
  card.setAttribute('rel', 'noopener noreferrer');

  const activityHtml = activity ? `<div class="service-activity ${activityType}">${activity}</div>` : '';

  card.innerHTML = `
    <img src="${service.icon}" alt="${service.name}" class="service-icon" onerror="this.style.display='none'">
    <div class="service-info">
      <div class="service-name">${service.name}</div>
      <div class="service-status ${status}">${status === 'loading' ? 'Checking...' : status}</div>
      ${activityHtml}
    </div>
  `;

  return card;
}

function renderServices() {
  const mainContainer = document.querySelector('main.container');

  // Get or create categories container
  let categoriesContainer = mainContainer.querySelector('.categories-container');
  if (!categoriesContainer) {
    categoriesContainer = document.createElement('div');
    categoriesContainer.className = 'categories-container';
    mainContainer.appendChild(categoriesContainer);
  }

  // Remove all existing category sections
  categoriesContainer.querySelectorAll('.category').forEach(section => section.remove());

  // Create category sections dynamically
  SERVICES.forEach(category => {
    if (category.services && category.services.length > 0) {
      const categoryIcon = category.icon || 'folder';
      const categoryColor = category.color || '#8b949e';
      const section = document.createElement('section');
      section.className = 'category';
      section.innerHTML = `
        <h2 style="color: ${categoryColor};">${getCategoryIconSVG(categoryIcon, categoryColor)}${escapeHtml(category.name)}</h2>
        <div class="services-grid" id="${category.id}"></div>
      `;

      categoriesContainer.appendChild(section);

      const grid = section.querySelector('.services-grid');
      category.services.forEach(service => {
        const card = createServiceCard(service);
        grid.appendChild(card);
      });
    }
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

let previousState = null;

async function updateServiceStatus() {
  try {
    const response = await fetch('/api/status', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      console.error('Status check failed:', response.status);
      return false;
    }

    const statuses = await response.json();

    // Check if there are any changes
    const currentState = JSON.stringify(statuses);
    const hasChanges = previousState !== currentState;
    previousState = currentState;

    let onlineCount = 0;
    let totalActiveItems = 0;

    statuses.forEach(service => {
      if (service.status === 'online') onlineCount++;

      // Count active items from activity string
      if (service.activity && service.activityType === 'active') {
        const match = service.activity.match(/(\d+)/);
        if (match) {
          totalActiveItems += parseInt(match[1]);
        }
      }

      const card = document.querySelector(`[data-path="${service.path}"]`);
      if (card) {
        card.className = `service-card ${service.status}`;
        const statusEl = card.querySelector('.service-status');
        statusEl.textContent = service.status;
        statusEl.className = `service-status ${service.status}`;

        // Update or add activity info
        const serviceInfo = card.querySelector('.service-info');
        let activityEl = serviceInfo.querySelector('.service-activity');

        if (service.activity) {
          if (!activityEl) {
            activityEl = document.createElement('div');
            activityEl.className = `service-activity ${service.activityType}`;
            serviceInfo.appendChild(activityEl);
          } else {
            activityEl.className = `service-activity ${service.activityType}`;
          }
          activityEl.textContent = service.activity;
        } else if (activityEl) {
          activityEl.remove();
        }
      }
    });

    // Handle Plex separately - mark as online without status check
    const plexCard = document.querySelector(`[data-path="https://plex.cirrolink.com"]`);
    if (plexCard) {
      plexCard.className = 'service-card online';
      const statusEl = plexCard.querySelector('.service-status');
      statusEl.textContent = 'online';
      statusEl.className = 'service-status online';
      onlineCount++; // Count Plex as online
    }

    // Update metrics
    document.getElementById('onlineCount').textContent = onlineCount;
    document.getElementById('totalCount').textContent = statuses.length + 1;
    document.getElementById('totalActivity').textContent = totalActiveItems > 0 ? `${totalActiveItems} active` : 'idle';

    // Update last update time
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    document.getElementById('lastUpdate').textContent = timeStr;

    return hasChanges;
  } catch (err) {
    console.error('Failed to update service status:', err);
    return false;
  }
}

async function updateServerInfo() {
  try {
    const response = await fetch('/api/server-info', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      console.error('Server info fetch failed:', response.status);
      return;
    }

    const info = await response.json();
    document.getElementById('serverHostname').textContent = info.hostname;
    document.getElementById('serverUptime').textContent = info.uptime;
    document.getElementById('serverCpu').textContent = info.cpu;
    document.getElementById('serverMemory').textContent = `${info.memory} (${info.memoryUsed}/${info.memoryTotal})`;
  } catch (err) {
    console.error('Failed to fetch server info:', err);
    document.getElementById('serverHostname').textContent = 'Error';
    document.getElementById('serverUptime').textContent = 'Error';
    document.getElementById('serverCpu').textContent = 'Error';
    document.getElementById('serverMemory').textContent = 'Error';
  }
}

// User menu dropdown toggle
const userMenuBtn = document.getElementById('userMenuBtn');
const userMenu = userMenuBtn.parentElement;

userMenuBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  userMenu.classList.toggle('open');
});

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
  if (!userMenu.contains(e.target)) {
    userMenu.classList.remove('open');
  }
});

document.getElementById('logoutBtn').addEventListener('click', async (e) => {
  e.preventDefault();

  try {
    await authenticatedFetch('/api/logout', {
      method: 'POST'
    });
  } catch (err) {
    console.error('Logout error:', err);
  } finally {
    window.location.href = '/login';
  }
});

async function init() {
  const authenticated = await checkAuth();
  if (!authenticated) return;

  // SECURITY: Fetch CSRF token on page load
  await fetchCsrfToken();

  // Load services from API (falls back to hardcoded if API fails)
  await loadServicesFromAPI();

  renderServices();
  await updateServiceStatus();
  await updateServerInfo();

  // Smart refresh: check for changes every 10 seconds
  // This will detect activity changes and update the UI immediately
  setInterval(async () => {
    const hasChanges = await updateServiceStatus();
    if (hasChanges) {
      console.log('Changes detected, UI updated');
    }
  }, 10000);

  // Update server info every 30 seconds (CPU, memory, uptime)
  setInterval(updateServerInfo, 30000);
}

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
