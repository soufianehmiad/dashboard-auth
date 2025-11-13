let currentServices = [];
let editingServiceId = null;
let csrfToken = null; // CSRF token for API requests

// Icon preview elements (will be initialized after DOM loads)
let iconInput, iconPreview, iconPlaceholder, pathInput;

// SECURITY: Fetch CSRF token from server
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

// SECURITY: Make authenticated API request with CSRF token
async function authenticatedFetch(url, options = {}) {
  // For POST, PUT, DELETE requests, add CSRF token
  if (options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
    // Ensure we have a CSRF token
    if (!csrfToken) {
      await fetchCsrfToken();
    }

    // Add CSRF token to headers
    options.headers = {
      ...options.headers,
      'x-csrf-token': csrfToken
    };
  }

  // Make the request
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options
  });

  // If 403 (CSRF validation failed), refresh token and retry once
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
  return `<svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 20px; height: 20px;">${path}</svg>`;
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

async function loadServices() {
  try {
    const response = await fetch('/api/services', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      throw new Error('Failed to load services');
    }

    const servicesData = await response.json();
    console.log('Services data from API:', servicesData);

    // Flatten services from categories into a single array
    currentServices = [];
    Object.entries(servicesData).forEach(([category, services]) => {
      services.forEach(service => {
        currentServices.push({ ...service, category });
      });
    });

    console.log('Current services after flatten:', currentServices);
    renderServices();
  } catch (err) {
    console.error('Failed to load services:', err);
    document.getElementById('servicesList').innerHTML = '<div class="loading">Failed to load services</div>';
  }
}

function renderServices() {
  const container = document.getElementById('servicesList');

  if (currentServices.length === 0) {
    container.innerHTML = '<div class="loading">No services found. Add your first service!</div>';
    return;
  }

  container.innerHTML = '';
  currentServices.forEach(service => {
    const item = createServiceItem(service);
    container.appendChild(item);
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function createServiceItem(service) {
  const item = document.createElement('div');
  item.className = 'service-item';

  console.log('Creating service item for:', service);

  // Find category data from currentCategories
  const categoryData = currentCategories.find(cat => cat.id === service.category);
  const categoryName = categoryData ? categoryData.name : service.category;
  const categoryColor = categoryData ? categoryData.color : '#58a6ff';

  // Escape all user-controlled data to prevent XSS
  const escapedName = escapeHtml(service.name);
  const escapedPath = escapeHtml(service.path);
  const escapedIcon = escapeHtml(service.icon);
  const escapedCategory = escapeHtml(service.category);
  const escapedCategoryName = escapeHtml(categoryName);
  const escapedCategoryColor = escapeHtml(categoryColor);

  const serviceType = service.serviceType || 'external';
  const serviceTypeLabel = serviceType === 'proxied' ? '🔄 Proxied' : '🔗 External';
  console.log(`Service "${service.name}": type=${serviceType}, proxyTarget=${service.proxyTarget}`);

  const proxyTargetHtml = serviceType === 'proxied' && service.proxyTarget
    ? `<div class="service-detail">
         <span class="service-detail-label">Target:</span>
         <span>${escapeHtml(service.proxyTarget)}</span>
       </div>`
    : '';

  item.innerHTML = `
    <img src="${escapedIcon}" alt="${escapedName}" class="service-icon-preview" onerror="this.style.display='none'">
    <div class="service-info">
      <div class="service-name">${escapedName}</div>
      <div class="service-details">
        <div class="service-detail">
          <span class="service-detail-label">Type:</span>
          <span style="font-size: 12px;">${serviceTypeLabel}</span>
        </div>
        <div class="service-detail">
          <span class="service-detail-label">Path:</span>
          <span>${escapedPath}</span>
        </div>
        ${proxyTargetHtml}
        <div class="service-detail">
          <span class="category-badge" style="background: ${escapedCategoryColor}; color: #ffffff;">${escapedCategoryName}</span>
        </div>
      </div>
    </div>
    <div class="service-actions">
      <button class="edit-btn" data-id="${service.id}">Edit</button>
      <button class="danger-btn" data-id="${service.id}">Delete</button>
    </div>
  `;

  // Add event listeners
  item.querySelector('.edit-btn').addEventListener('click', () => openEditModal(service));
  item.querySelector('.danger-btn').addEventListener('click', () => deleteService(service.id, service.name));

  return item;
}

function openAddModal() {
  editingServiceId = null;
  document.getElementById('modalTitle').textContent = 'Add Service';
  document.getElementById('serviceForm').reset();
  document.getElementById('serviceId').value = '';

  // Reset icon preview
  iconPreview.classList.remove('show');
  iconPlaceholder.textContent = 'Preview';

  // Reset service type fields
  handleServiceTypeChange();

  document.getElementById('serviceModal').classList.add('show');
}

function openEditModal(service) {
  editingServiceId = service.id;
  document.getElementById('modalTitle').textContent = 'Edit Service';
  document.getElementById('serviceId').value = service.id;
  document.getElementById('serviceName').value = service.name;

  // Set service type and related fields
  const serviceType = service.serviceType || (service.path.startsWith('http') ? 'external' : 'proxied');
  document.getElementById('serviceType').value = serviceType;
  handleServiceTypeChange();

  if (serviceType === 'external') {
    document.getElementById('externalUrl').value = service.path;
  } else {
    document.getElementById('proxyPath').value = service.path;
    document.getElementById('proxyTarget').value = service.proxyTarget || '';
  }

  document.getElementById('serviceIcon').value = service.icon;
  document.getElementById('serviceCategory').value = service.category;
  document.getElementById('serviceApiUrl').value = service.apiUrl || '';
  document.getElementById('serviceApiKey').value = service.apiKeyEnv || '';
  document.getElementById('serviceOrder').value = 0;

  // Update icon preview
  updateIconPreview();

  document.getElementById('serviceModal').classList.add('show');
}

function closeModal() {
  document.getElementById('serviceModal').classList.remove('show');
  editingServiceId = null;
}

async function saveService(event) {
  event.preventDefault();

  const serviceType = document.getElementById('serviceType').value;
  let path, proxyTarget;

  if (serviceType === 'external') {
    path = document.getElementById('externalUrl').value;
    proxyTarget = null;
  } else if (serviceType === 'proxied') {
    path = document.getElementById('proxyPath').value;
    proxyTarget = document.getElementById('proxyTarget').value;

    // Validate proxy target has protocol
    if (!proxyTarget.startsWith('http://') && !proxyTarget.startsWith('https://')) {
      alert('Backend URL must start with http:// or https://\n\nExample: https://youtube.com');
      return;
    }

    // Validate path starts with /
    if (!path.startsWith('/')) {
      alert('Proxy path must start with /\n\nExample: /youtube');
      return;
    }
  } else {
    alert('Please select a service type');
    return;
  }

  const formData = {
    name: document.getElementById('serviceName').value,
    path: path,
    service_type: serviceType,
    proxy_target: proxyTarget,
    icon_url: document.getElementById('serviceIcon').value,
    category: document.getElementById('serviceCategory').value,
    api_url: document.getElementById('serviceApiUrl').value || null,
    api_key_env: document.getElementById('serviceApiKey').value || null,
    display_order: parseInt(document.getElementById('serviceOrder').value) || 0
  };

  try {
    const url = editingServiceId
      ? `/api/services/${editingServiceId}`
      : '/api/services';

    const method = editingServiceId ? 'PUT' : 'POST';

    const response = await authenticatedFetch(url, {
      method: method,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });

    const result = await response.json();

    if (!response.ok) {
      alert(result.error || 'Failed to save service');
      return;
    }

    // Show nginx status if there were issues
    if (result.nginx && result.nginx.warning) {
      alert(`Service saved!\n\nWarning: ${result.nginx.warning}\n\nYou may need to configure nginx manually or check container permissions.`);
    }

    closeModal();
    await loadServices();
    // Reload locations if they've been loaded
    if (currentLocations.length > 0) {
      await loadNginxLocations();
    }
  } catch (err) {
    console.error('Failed to save service:', err);
    alert('Failed to save service');
  }
}

async function deleteService(id, name) {
  if (!confirm(`Are you sure you want to delete "${name}"?\n\nThis will also remove any nginx proxy configuration associated with this service.`)) {
    return;
  }

  try {
    const response = await authenticatedFetch(`/api/services/${id}`, {
      method: 'DELETE',
      credentials: 'same-origin'
    });

    const result = await response.json();

    if (!response.ok) {
      alert(result.error || 'Failed to delete service');
      return;
    }

    await loadServices();
    // Reload locations if they've been loaded
    if (currentLocations.length > 0) {
      await loadNginxLocations();
    }
  } catch (err) {
    console.error('Failed to delete service:', err);
    alert('Failed to delete service');
  }
}

// Service type handling
function handleServiceTypeChange() {
  const serviceType = document.getElementById('serviceType').value;
  const externalUrlGroup = document.getElementById('externalUrlGroup');
  const proxyPathGroup = document.getElementById('proxyPathGroup');
  const proxyTargetGroup = document.getElementById('proxyTargetGroup');

  const externalUrl = document.getElementById('externalUrl');
  const proxyPath = document.getElementById('proxyPath');
  const proxyTarget = document.getElementById('proxyTarget');

  if (serviceType === 'external') {
    externalUrlGroup.style.display = 'block';
    proxyPathGroup.style.display = 'none';
    proxyTargetGroup.style.display = 'none';
    externalUrl.required = true;
    proxyPath.required = false;
    proxyTarget.required = false;
  } else if (serviceType === 'proxied') {
    externalUrlGroup.style.display = 'none';
    proxyPathGroup.style.display = 'block';
    proxyTargetGroup.style.display = 'block';
    externalUrl.required = false;
    proxyPath.required = true;
    proxyTarget.required = true;
  } else {
    externalUrlGroup.style.display = 'none';
    proxyPathGroup.style.display = 'none';
    proxyTargetGroup.style.display = 'none';
    externalUrl.required = false;
    proxyPath.required = false;
    proxyTarget.required = false;
  }
}

// Initialize icon preview elements
function initIconPreview() {
  iconInput = document.getElementById('serviceIcon');
  iconPreview = document.getElementById('iconPreview');
  iconPlaceholder = document.getElementById('iconPlaceholder');

  iconInput.addEventListener('input', updateIconPreview);

  // Add service type change listener
  document.getElementById('serviceType').addEventListener('change', handleServiceTypeChange);

  // Auto-generate favicon URL from external URL
  document.getElementById('externalUrl').addEventListener('blur', () => {
    const url = document.getElementById('externalUrl').value.trim();
    const currentIcon = iconInput.value.trim();

    if (!currentIcon && url) {
      try {
        const urlObj = new URL(url);
        iconInput.value = `https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=128`;
        updateIconPreview();
      } catch (e) {
        // Invalid URL, ignore
      }
    }
  });
}

function updateIconPreview() {
  const iconUrl = iconInput.value.trim();
  if (iconUrl) {
    iconPreview.src = iconUrl;
    iconPreview.classList.add('show');

    iconPreview.onerror = () => {
      iconPreview.classList.remove('show');
      iconPlaceholder.textContent = 'Error';
    };
  } else {
    iconPreview.classList.remove('show');
    iconPlaceholder.textContent = 'Preview';
  }
}

// Event listeners
document.getElementById('addServiceBtn').addEventListener('click', openAddModal);
document.getElementById('closeModal').addEventListener('click', closeModal);
document.getElementById('cancelBtn').addEventListener('click', closeModal);
document.getElementById('serviceForm').addEventListener('submit', saveService);

// Close modal when clicking outside
document.getElementById('serviceModal').addEventListener('click', (e) => {
  if (e.target.id === 'serviceModal') {
    closeModal();
  }
});

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
      method: 'POST',
      credentials: 'same-origin'
    });
  } catch (err) {
    console.error('Logout error:', err);
  } finally {
    window.location.href = '/login';
  }
});

// Nginx config management
let originalConfig = '';
let isEditMode = false;
let currentLocations = [];
let currentCategories = [];

async function loadNginxLocations() {
  try {
    const response = await fetch('/api/nginx/locations', {
      credentials: 'same-origin'
    });

    if (!response.ok) {
      throw new Error('Failed to load nginx locations');
    }

    const data = await response.json();
    currentLocations = data.locations;
    renderNginxLocations();
  } catch (err) {
    console.error('Failed to load locations:', err);
    document.getElementById('locationsList').innerHTML = '<div class="loading">Failed to load proxy locations</div>';
  }
}

function renderNginxLocations() {
  const container = document.getElementById('locationsList');

  if (currentLocations.length === 0) {
    container.innerHTML = '<div class="loading">No proxy locations configured</div>';
    return;
  }

  container.innerHTML = '';
  currentLocations.forEach(location => {
    const item = document.createElement('div');
    item.className = 'service-item';

    item.innerHTML = `
      <div class="icon-container">
        <svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="18" cy="18" r="3"/>
          <circle cx="6" cy="6" r="3"/>
          <path d="M13 6h3a2 2 0 012 2v7"/>
          <path d="M6 9v12"/>
        </svg>
      </div>
      <div class="service-info">
        <div class="service-name">${escapeHtml(location.name)}</div>
        <div class="service-details">
          <div class="service-detail">
            <span class="service-detail-label">Path:</span>
            <span>${escapeHtml(location.path)}</span>
          </div>
          <div class="service-detail">
            <span class="service-detail-label">Target:</span>
            <span>${escapeHtml(location.target)}</span>
          </div>
        </div>
      </div>
      <div class="service-actions">
        <button class="danger-btn delete-location-btn">Delete</button>
      </div>
    `;

    item.querySelector('.delete-location-btn').addEventListener('click', () => deleteNginxLocation(location));
    container.appendChild(item);
  });
}

async function deleteNginxLocation(location) {
  if (!confirm(`Are you sure you want to delete the proxy location "${location.path}"?\n\nThis will remove the nginx configuration for this path.`)) {
    return;
  }

  try {
    const response = await authenticatedFetch('/api/nginx/locations', {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({
        path: location.path,
        name: location.name
      })
    });

    const result = await response.json();

    if (!response.ok) {
      showNginxMessage(`Failed to delete location: ${result.error}`, 'error');
      return;
    }

    showNginxMessage(`Location "${location.path}" deleted successfully`, 'success');
    await loadNginxLocations();
  } catch (err) {
    console.error('Failed to delete location:', err);
    showNginxMessage('Failed to delete location', 'error');
  }
}

async function loadNginxConfig() {
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
    showNginxMessage('Failed to load nginx configuration', 'error');
    document.getElementById('loadingOverlay').innerHTML = '<span style="color: #f85149;">Failed to load configuration</span>';
  }
}

function showNginxMessage(text, type = 'info') {
  const messageDiv = document.getElementById('nginxMessage');
  const locationsMessageDiv = document.getElementById('locationsMessage');

  [messageDiv, locationsMessageDiv].forEach(div => {
    if (!div) return;
    div.textContent = text;
    div.style.display = 'block';

    if (type === 'error') {
      div.style.background = '#f85149';
      div.style.color = '#ffffff';
      div.style.border = '1px solid #f85149';
    } else if (type === 'success') {
      div.style.background = '#238636';
      div.style.color = '#ffffff';
      div.style.border = '1px solid #2ea043';
    } else {
      div.style.background = '#1f6feb';
      div.style.color = '#ffffff';
      div.style.border = '1px solid #1f6feb';
    }
  });

  setTimeout(() => {
    if (messageDiv) messageDiv.style.display = 'none';
    if (locationsMessageDiv) locationsMessageDiv.style.display = 'none';
  }, 5000);
}

function enableEditMode() {
  isEditMode = true;
  document.getElementById('configEditor').readOnly = false;
  document.getElementById('configEditor').style.borderColor = '#58a6ff';
  document.getElementById('editBtn').style.display = 'none';
  document.getElementById('saveBtn').style.display = 'inline-block';
  document.getElementById('cancelNginxBtn').style.display = 'inline-block';
  document.getElementById('reloadBtn').style.display = 'none';
  showNginxMessage('Edit mode enabled. Make your changes and click Save.', 'info');
}

function disableEditMode() {
  isEditMode = false;
  document.getElementById('configEditor').readOnly = true;
  document.getElementById('configEditor').style.borderColor = '#30363d';
  document.getElementById('configEditor').value = originalConfig;
  document.getElementById('editBtn').style.display = 'inline-block';
  document.getElementById('saveBtn').style.display = 'none';
  document.getElementById('cancelNginxBtn').style.display = 'none';
  document.getElementById('reloadBtn').style.display = 'inline-block';
}

async function saveNginxConfig() {
  const newConfig = document.getElementById('configEditor').value;

  if (newConfig === originalConfig) {
    showNginxMessage('No changes detected', 'info');
    disableEditMode();
    return;
  }

  if (!confirm('Are you sure you want to save these changes? Invalid syntax may break nginx.')) {
    return;
  }

  try {
    const response = await authenticatedFetch('/api/nginx/config', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ config: newConfig })
    });

    const result = await response.json();

    if (!response.ok) {
      showNginxMessage(`Error: ${result.error}${result.details ? '\n\n' + result.details : ''}`, 'error');
      return;
    }

    originalConfig = newConfig;
    showNginxMessage('Configuration saved and nginx reloaded successfully!', 'success');
    disableEditMode();
  } catch (err) {
    console.error('Failed to save config:', err);
    showNginxMessage('Failed to save configuration', 'error');
  }
}

async function reloadNginx() {
  if (!confirm('Are you sure you want to reload nginx?')) {
    return;
  }

  try {
    const response = await authenticatedFetch('/api/nginx/config', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ config: originalConfig })
    });

    const result = await response.json();

    if (!response.ok) {
      showNginxMessage(`Reload failed: ${result.error}`, 'error');
      return;
    }

    showNginxMessage('Nginx reloaded successfully!', 'success');
  } catch (err) {
    console.error('Failed to reload nginx:', err);
    showNginxMessage('Failed to reload nginx', 'error');
  }
}

// Category Management

async function loadCategories() {
  try {
    const response = await fetch('/api/categories', {
      credentials: 'same-origin'
    });
    const data = await response.json();
    currentCategories = data;
    renderCategories();

    // Update service form category dropdown
    await updateCategoryDropdown();
  } catch (error) {
    console.error('Error loading categories:', error);
    showCategoriesMessage('Failed to load categories', 'error');
  }
}

function renderCategories() {
  const list = document.getElementById('categoriesList');
  list.innerHTML = '';

  if (currentCategories.length === 0) {
    list.innerHTML = '<div class="loading">No categories found.</div>';
    return;
  }

  currentCategories.forEach(category => {
    const item = document.createElement('div');
    item.className = 'service-item';
    const categoryColor = category.color || '#58a6ff';
    const categoryIcon = category.icon || 'folder';
    item.innerHTML = `
      <div class="icon-container">
        ${getCategoryIconSVG(categoryIcon, categoryColor)}
      </div>
      <div class="service-info">
        <div class="service-name">${escapeHtml(category.name)}</div>
        <div class="service-details">
          <div class="service-detail">
            <span class="service-detail-label">ID:</span>
            <span>${escapeHtml(category.id)}</span>
          </div>
          <div class="service-detail">
            <span class="service-detail-label">Order:</span>
            <span>${category.display_order}</span>
          </div>
          <div class="service-detail">
            <span class="category-badge" style="background: ${escapeHtml(categoryColor)}; color: #ffffff;">${escapeHtml(category.name)}</span>
          </div>
        </div>
      </div>
      <div class="service-actions">
        <button class="secondary-btn edit-category-btn">Edit</button>
        <button class="danger-btn delete-category-btn">Delete</button>
      </div>
    `;

    item.querySelector('.edit-category-btn').addEventListener('click', () => editCategory(category));
    item.querySelector('.delete-category-btn').addEventListener('click', () => deleteCategory(category));

    list.appendChild(item);
  });
}

async function updateCategoryDropdown() {
  const categorySelect = document.getElementById('serviceCategory');
  if (!categorySelect) return;

  // Save current selection
  const currentValue = categorySelect.value;

  // Clear and rebuild options
  categorySelect.innerHTML = '<option value="">Select category...</option>';

  currentCategories.forEach(cat => {
    const option = document.createElement('option');
    option.value = cat.id;
    option.textContent = cat.name;
    categorySelect.appendChild(option);
  });

  // Restore selection
  if (currentValue) {
    categorySelect.value = currentValue;
  }
}

function showCategoriesMessage(message, type = 'success') {
  const messageEl = document.getElementById('categoriesMessage');
  messageEl.textContent = message;
  messageEl.className = `message ${type}`;
  messageEl.style.display = 'block';
  messageEl.style.background = type === 'error' ? '#da3633' : type === 'warning' ? '#d29922' : '#238636';

  setTimeout(() => {
    messageEl.style.display = 'none';
  }, 5000);
}

// Category modal management
const categoryModal = document.getElementById('categoryModal');
const categoryForm = document.getElementById('categoryForm');
const addCategoryBtn = document.getElementById('addCategoryBtn');
const closeCategoryModalBtn = document.getElementById('closeCategoryModal');
const cancelCategoryBtn = document.getElementById('cancelCategoryBtn');

addCategoryBtn.addEventListener('click', () => {
  document.getElementById('categoryModalTitle').textContent = 'Add Category';
  document.getElementById('categoryIdOriginal').value = '';
  document.getElementById('categoryId').value = '';
  document.getElementById('categoryId').disabled = false;
  document.getElementById('categoryName').value = '';
  document.getElementById('categoryIcon').value = 'folder';
  document.getElementById('categoryColor').value = '#58a6ff';
  document.getElementById('categoryOrder').value = '0';
  categoryModal.style.display = 'block';
});

closeCategoryModalBtn.addEventListener('click', () => {
  categoryModal.style.display = 'none';
});

cancelCategoryBtn.addEventListener('click', () => {
  categoryModal.style.display = 'none';
});

categoryForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  await saveCategory();
});

function editCategory(category) {
  document.getElementById('categoryModalTitle').textContent = 'Edit Category';
  document.getElementById('categoryIdOriginal').value = category.id;
  document.getElementById('categoryId').value = category.id;
  document.getElementById('categoryId').disabled = true; // Cannot change ID
  document.getElementById('categoryName').value = category.name;
  document.getElementById('categoryIcon').value = category.icon || 'folder';
  document.getElementById('categoryColor').value = category.color || '#58a6ff';
  document.getElementById('categoryOrder').value = category.display_order;
  categoryModal.style.display = 'block';
}

async function saveCategory() {
  const originalId = document.getElementById('categoryIdOriginal').value;
  const id = document.getElementById('categoryId').value.trim();
  const name = document.getElementById('categoryName').value.trim();
  const icon = document.getElementById('categoryIcon').value;
  const color = document.getElementById('categoryColor').value;
  const display_order = parseInt(document.getElementById('categoryOrder').value) || 0;

  if (!id || !name) {
    showCategoriesMessage('Category ID and name are required', 'error');
    return;
  }

  const isEdit = originalId !== '';
  const method = isEdit ? 'PUT' : 'POST';
  const url = isEdit ? `/api/categories/${originalId}` : '/api/categories';

  try {
    const response = await authenticatedFetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, name, display_order, color, icon })
    });

    const data = await response.json();

    if (!response.ok) {
      showCategoriesMessage(data.error || 'Failed to save category', 'error');
      return;
    }

    showCategoriesMessage(`Category ${isEdit ? 'updated' : 'created'} successfully`, 'success');
    categoryModal.style.display = 'none';
    await loadCategories();
  } catch (error) {
    console.error('Error saving category:', error);
    showCategoriesMessage('Failed to save category', 'error');
  }
}

async function deleteCategory(category) {
  if (!confirm(`Are you sure you want to delete the category "${category.name}"?\n\nThis will fail if any services are assigned to this category.`)) {
    return;
  }

  try {
    const response = await authenticatedFetch(`/api/categories/${category.id}`, {
      method: 'DELETE'
    });

    const data = await response.json();

    if (!response.ok) {
      if (data.serviceCount) {
        showCategoriesMessage(data.message, 'error');
      } else {
        showCategoriesMessage(data.error || 'Failed to delete category', 'error');
      }
      return;
    }

    showCategoriesMessage('Category deleted successfully', 'success');
    await loadCategories();
  } catch (error) {
    console.error('Error deleting category:', error);
    showCategoriesMessage('Failed to delete category', 'error');
  }
}

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', function() {
    const tabName = this.getAttribute('data-tab');

    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    this.classList.add('active');

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

    if (tabName === 'services') {
      document.getElementById('servicesTab').classList.add('active');
    } else if (tabName === 'categories') {
      document.getElementById('categoriesTab').classList.add('active');
      // Load categories when tab is opened for the first time
      if (currentCategories.length === 0) {
        loadCategories();
      }
    } else if (tabName === 'locations') {
      document.getElementById('locationsTab').classList.add('active');
      // Load locations when tab is opened for the first time
      if (currentLocations.length === 0) {
        loadNginxLocations();
      }
    } else if (tabName === 'nginx') {
      document.getElementById('nginxTab').classList.add('active');
      // Load nginx config when tab is opened for the first time
      if (!originalConfig) {
        loadNginxConfig();
      }
    }
  });
});

// Nginx config event listeners
document.getElementById('editBtn').addEventListener('click', enableEditMode);
document.getElementById('saveBtn').addEventListener('click', saveNginxConfig);
document.getElementById('cancelNginxBtn').addEventListener('click', disableEditMode);
document.getElementById('reloadBtn').addEventListener('click', reloadNginx);

async function init() {
  const authenticated = await checkAuth();
  if (!authenticated) return;

  // SECURITY: Fetch CSRF token on page load
  await fetchCsrfToken();

  // Initialize icon preview functionality
  initIconPreview();

  // Load categories first so the dropdown is populated
  await loadCategories();

  await loadServices();
}

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
