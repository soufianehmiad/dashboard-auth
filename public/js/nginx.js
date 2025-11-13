let originalConfig = '';
let isEditMode = false;

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

async function loadConfig() {
  try {
    const response = await fetch('/api/nginx/config', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      throw new Error('Failed to load nginx config');
    }

    const data = await response.json();
    originalConfig = data.config;
    document.getElementById('configEditor').value = data.config;
    document.getElementById('loadingOverlay').style.display = 'none';
  } catch (err) {
    console.error('Failed to load config:', err);
    showMessage('Failed to load nginx configuration', 'error');
    document.getElementById('loadingOverlay').innerHTML = '<span style="color: #f85149;">Failed to load configuration</span>';
  }
}

function showMessage(text, type = 'info') {
  const messageDiv = document.getElementById('message');
  messageDiv.textContent = text;
  messageDiv.style.display = 'block';

  if (type === 'error') {
    messageDiv.style.background = '#f85149';
    messageDiv.style.color = '#ffffff';
    messageDiv.style.border = '1px solid #f85149';
  } else if (type === 'success') {
    messageDiv.style.background = '#238636';
    messageDiv.style.color = '#ffffff';
    messageDiv.style.border = '1px solid #2ea043';
  } else {
    messageDiv.style.background = '#1f6feb';
    messageDiv.style.color = '#ffffff';
    messageDiv.style.border = '1px solid #1f6feb';
  }

  // Auto-hide after 5 seconds
  setTimeout(() => {
    messageDiv.style.display = 'none';
  }, 5000);
}

function enableEditMode() {
  isEditMode = true;
  document.getElementById('configEditor').readOnly = false;
  document.getElementById('configEditor').style.borderColor = '#58a6ff';
  document.getElementById('editBtn').style.display = 'none';
  document.getElementById('saveBtn').style.display = 'inline-block';
  document.getElementById('cancelBtn').style.display = 'inline-block';
  document.getElementById('reloadBtn').style.display = 'none';
  showMessage('Edit mode enabled. Make your changes and click Save.', 'info');
}

function disableEditMode() {
  isEditMode = false;
  document.getElementById('configEditor').readOnly = true;
  document.getElementById('configEditor').style.borderColor = '#30363d';
  document.getElementById('configEditor').value = originalConfig;
  document.getElementById('editBtn').style.display = 'inline-block';
  document.getElementById('saveBtn').style.display = 'none';
  document.getElementById('cancelBtn').style.display = 'none';
  document.getElementById('reloadBtn').style.display = 'inline-block';
}

async function saveConfig() {
  const newConfig = document.getElementById('configEditor').value;

  if (newConfig === originalConfig) {
    showMessage('No changes detected', 'info');
    disableEditMode();
    return;
  }

  if (!confirm('Are you sure you want to save these changes? Invalid syntax may break nginx.')) {
    return;
  }

  try {
    const response = await fetch('/api/nginx/config', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ config: newConfig })
    });

    const result = await response.json();

    if (!response.ok) {
      showMessage(`Error: ${result.error}${result.details ? '\n\n' + result.details : ''}`, 'error');
      return;
    }

    originalConfig = newConfig;
    showMessage('Configuration saved and nginx reloaded successfully!', 'success');
    disableEditMode();
  } catch (err) {
    console.error('Failed to save config:', err);
    showMessage('Failed to save configuration', 'error');
  }
}

async function reloadNginx() {
  if (!confirm('Are you sure you want to reload nginx? This will apply the current configuration.')) {
    return;
  }

  try {
    // We can use the save endpoint with the current config to trigger a reload
    const response = await fetch('/api/nginx/config', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ config: originalConfig })
    });

    const result = await response.json();

    if (!response.ok) {
      showMessage(`Reload failed: ${result.error}${result.details ? '\n\n' + result.details : ''}`, 'error');
      return;
    }

    showMessage('Nginx reloaded successfully!', 'success');
  } catch (err) {
    console.error('Failed to reload nginx:', err);
    showMessage('Failed to reload nginx', 'error');
  }
}

// Event listeners
document.getElementById('editBtn').addEventListener('click', enableEditMode);
document.getElementById('saveBtn').addEventListener('click', saveConfig);
document.getElementById('cancelBtn').addEventListener('click', disableEditMode);
document.getElementById('reloadBtn').addEventListener('click', reloadNginx);

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

  await loadConfig();
}

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
