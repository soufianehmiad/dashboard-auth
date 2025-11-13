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
    const response = await fetch('/api/services', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      console.warn('Failed to load services from API, using fallback');
      return false;
    }

    const servicesData = await response.json();
    SERVICES = servicesData;
    console.log('Services loaded from API');
    return true;
  } catch (err) {
    console.warn('Failed to load services from API, using fallback:', err);
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
  const categories = {
    contentManagement: document.getElementById('contentManagement'),
    downloadClients: document.getElementById('downloadClients'),
    managementAnalytics: document.getElementById('managementAnalytics')
  };

  Object.entries(SERVICES).forEach(([category, services]) => {
    const container = categories[category];
    container.innerHTML = ''; // Clear loading state
    services.forEach(service => {
      const card = createServiceCard(service);
      container.appendChild(card);
    });
  });
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
    await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin'
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
