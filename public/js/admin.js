let currentServices = [];
let editingServiceId = null;

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

    // Flatten services from categories into a single array
    currentServices = [];
    Object.entries(servicesData).forEach(([category, services]) => {
      services.forEach(service => {
        currentServices.push({ ...service, category });
      });
    });

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

  const categoryName = {
    contentManagement: 'Content Management',
    downloadClients: 'Download Clients',
    managementAnalytics: 'Management & Analytics'
  }[service.category] || service.category;

  // Escape all user-controlled data to prevent XSS
  const escapedName = escapeHtml(service.name);
  const escapedPath = escapeHtml(service.path);
  const escapedIcon = escapeHtml(service.icon);
  const escapedCategory = escapeHtml(service.category);
  const escapedCategoryName = escapeHtml(categoryName);

  item.innerHTML = `
    <img src="${escapedIcon}" alt="${escapedName}" class="service-icon-preview" onerror="this.style.display='none'">
    <div class="service-info">
      <div class="service-name">${escapedName}</div>
      <div class="service-details">
        <div class="service-detail">
          <span class="service-detail-label">Path:</span>
          <span>${escapedPath}</span>
        </div>
        <div class="service-detail">
          <span class="category-badge ${escapedCategory}">${escapedCategoryName}</span>
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
  document.getElementById('serviceModal').classList.add('show');
}

function openEditModal(service) {
  editingServiceId = service.id;
  document.getElementById('modalTitle').textContent = 'Edit Service';
  document.getElementById('serviceId').value = service.id;
  document.getElementById('serviceName').value = service.name;
  document.getElementById('servicePath').value = service.path;
  document.getElementById('serviceIcon').value = service.icon;
  document.getElementById('serviceCategory').value = service.category;
  document.getElementById('serviceApiUrl').value = service.apiUrl || '';
  document.getElementById('serviceApiKey').value = service.apiKeyEnv || '';
  document.getElementById('serviceOrder').value = 0; // We don't have this in the API response yet
  document.getElementById('serviceModal').classList.add('show');
}

function closeModal() {
  document.getElementById('serviceModal').classList.remove('show');
  editingServiceId = null;
}

async function saveService(event) {
  event.preventDefault();

  const formData = {
    name: document.getElementById('serviceName').value,
    path: document.getElementById('servicePath').value,
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

    const response = await fetch(url, {
      method: method,
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify(formData)
    });

    const result = await response.json();

    if (!response.ok) {
      alert(result.error || 'Failed to save service');
      return;
    }

    closeModal();
    await loadServices();
  } catch (err) {
    console.error('Failed to save service:', err);
    alert('Failed to save service');
  }
}

async function deleteService(id, name) {
  if (!confirm(`Are you sure you want to delete "${name}"?`)) {
    return;
  }

  try {
    const response = await fetch(`/api/services/${id}`, {
      method: 'DELETE',
      credentials: 'same-origin'
    });

    const result = await response.json();

    if (!response.ok) {
      alert(result.error || 'Failed to delete service');
      return;
    }

    await loadServices();
  } catch (err) {
    console.error('Failed to delete service:', err);
    alert('Failed to delete service');
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

  await loadServices();
}

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
