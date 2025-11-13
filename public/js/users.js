// Global state
let currentUser = null;
let csrfToken = null;
let allUsers = [];

// Role display names and hierarchy
const ROLE_NAMES = {
  'super_admin': 'Super Admin',
  'admin': 'Administrator',
  'power_user': 'Power User',
  'user': 'User',
  'read_only': 'Read Only'
};

const ROLE_HIERARCHY = {
  'super_admin': 5,
  'admin': 4,
  'power_user': 3,
  'user': 2,
  'read_only': 1
};

// Toast Notifications
function showToast(type, title, message) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ⓘ';

  toast.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div class="toast-content">
      <div class="toast-title">${title}</div>
      ${message ? `<div class="toast-message">${message}</div>` : ''}
    </div>
    <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
  `;

  container.appendChild(toast);

  // Auto-remove after 5 seconds
  setTimeout(() => {
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

function showSuccess(message) {
  showToast('success', 'Success', message);
}

function showError(message) {
  showToast('error', 'Error', message);
}

function showInfo(message) {
  showToast('info', 'Info', message);
}

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

// Authentication check
async function checkAuth() {
  try {
    const response = await fetch('/api/verify', { credentials: 'same-origin' });
    if (!response.ok) {
      const returnPath = encodeURIComponent(window.location.pathname);
      window.location.href = `/login?return=${returnPath}`;
      return false;
    }
    const data = await response.json();

    // Store current user for permission checks
    currentUser = data;

    // Update header with user info
    updateUserInfo(data);

    // Check if user has admin permission
    if (!data.role || !['super_admin', 'admin'].includes(data.role)) {
      // Redirect non-admins
      window.location.href = '/';
      return false;
    }

    return true;
  } catch (err) {
    console.error('Auth check failed:', err);
    window.location.href = '/login';
    return false;
  }
}

// Update user info in header
function updateUserInfo(user) {
  const usernameEl = document.getElementById('username');
  if (usernameEl) {
    usernameEl.textContent = user.displayName || user.username;
  }

  // Show create user button if user has permission
  if (user.role === 'super_admin' || user.role === 'admin') {
    const createBtn = document.getElementById('createUserBtn');
    if (createBtn) {
      createBtn.style.display = 'inline-block';
    }

    // Show "Manage Users" link in navigation
    const manageUsersLink = document.getElementById('manageUsersLink');
    if (manageUsersLink) {
      manageUsersLink.style.display = 'flex';
    }
  }
}

// Permission helpers
function canManageUser(user) {
  if (!currentUser || !user) return false;

  // Can't manage yourself for certain actions
  if (user.id === currentUser.id) return false;

  // Super admin can manage everyone except themselves
  if (currentUser.role === 'super_admin') return true;

  // Admin can manage everyone except super_admins
  if (currentUser.role === 'admin' && user.role !== 'super_admin') return true;

  return false;
}

function canAssignRole(role) {
  if (!currentUser) return false;

  // Super admin can assign any role
  if (currentUser.role === 'super_admin') return true;

  // Admin can assign any role except super_admin
  if (currentUser.role === 'admin' && role !== 'super_admin') return true;

  return false;
}

function getAssignableRoles() {
  const roles = [];

  if (currentUser.role === 'super_admin') {
    // Super admin can assign all roles
    roles.push('super_admin', 'admin', 'power_user', 'user', 'read_only');
  } else if (currentUser.role === 'admin') {
    // Admin can assign all except super_admin
    roles.push('admin', 'power_user', 'user', 'read_only');
  }

  return roles;
}

// Utility functions
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatDate(dateString) {
  if (!dateString) return 'Never';
  const date = new Date(dateString);
  return date.toLocaleString();
}

function getRoleDisplayName(role) {
  return ROLE_NAMES[role] || role;
}

// Message display
function showMessage(elementId, text, isError = false) {
  const messageDiv = document.getElementById(elementId);
  if (!messageDiv) return;

  messageDiv.textContent = text;
  messageDiv.style.display = 'block';
  messageDiv.className = isError ? 'message error' : 'message success';

  setTimeout(() => {
    messageDiv.style.display = 'none';
  }, 5000);
}

function showGlobalMessage(text, isError = false) {
  showMessage('globalMessage', text, isError);
}

// Load users from API
async function loadUsers() {
  try {
    const response = await fetch('/api/users', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Failed to load users');

    const users = await response.json();
    allUsers = users;
    renderUserTable(users);
  } catch (err) {
    console.error('Load users error:', err);
    showError('Failed to load users');
  }
}

// Render user table
function renderUserTable(users) {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = '';

  if (users.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="7" class="loading">No users found</td>';
    tbody.appendChild(tr);
    return;
  }

  users.forEach(user => {
    const tr = document.createElement('tr');
    const canManage = canManageUser(user);

    tr.innerHTML = `
      <td>${escapeHtml(user.username)}</td>
      <td>${escapeHtml(user.display_name || '-')}</td>
      <td>${escapeHtml(user.email || '-')}</td>
      <td><span class="role-badge ${user.role}">${getRoleDisplayName(user.role)}</span></td>
      <td><span class="status-badge ${user.is_active ? 'active' : 'inactive'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
      <td>${formatDate(user.last_login_at)}</td>
      <td class="actions">
        ${canManage ? `
          <button onclick="openEditModal(${user.id})" class="btn-icon" title="Edit">✎</button>
          <button onclick="openResetPasswordModal(${user.id})" class="btn-icon" title="Reset Password">🔑</button>
          ${currentUser.role === 'super_admin' ? `
            <button onclick="openDeleteModal(${user.id})" class="btn-icon btn-danger" title="Deactivate">✕</button>
          ` : ''}
        ` : '<span class="text-muted">No access</span>'}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Populate role select dropdowns
function populateRoleSelect(selectId) {
  const select = document.getElementById(selectId);
  if (!select) return;

  // Clear existing options except the first one (if it's a placeholder)
  const firstOption = select.options[0];
  select.innerHTML = '';
  if (firstOption && firstOption.value === '') {
    select.appendChild(firstOption);
  }

  const assignableRoles = getAssignableRoles();
  assignableRoles.forEach(role => {
    const option = document.createElement('option');
    option.value = role;
    option.textContent = getRoleDisplayName(role);
    select.appendChild(option);
  });
}

// Modal management
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('show');
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('show');
  }

  // Clear any form messages
  const messageIds = ['createUserMessage', 'editUserMessage', 'resetPasswordMessage', 'deleteUserMessage'];
  messageIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
}

// Create User Modal
function openCreateModal() {
  populateRoleSelect('createRole');
  document.getElementById('createUserForm').reset();
  openModal('createUserModal');
}

async function createUser(userData) {
  try {
    const response = await authenticatedFetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to create user');
    }

    showSuccess('User created successfully');
    closeModal('createUserModal');
    loadUsers();
  } catch (err) {
    console.error('Create user error:', err);
    showError(err.message || 'Failed to create user');
    showMessage('createUserMessage', err.message, true);
  }
}

// Edit User Modal
function openEditModal(userId) {
  const user = allUsers.find(u => u.id === userId);
  if (!user) return;

  populateRoleSelect('editRole');

  document.getElementById('editUserId').value = user.id;
  document.getElementById('editUsername').value = user.username;
  document.getElementById('editDisplayName').value = user.display_name || '';
  document.getElementById('editEmail').value = user.email || '';
  document.getElementById('editRole').value = user.role;
  document.getElementById('editActive').value = user.is_active ? '1' : '0';

  openModal('editUserModal');
}

async function updateUser(userId, userData) {
  try {
    const response = await authenticatedFetch(`/api/users/${userId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to update user');
    }

    showSuccess('User updated successfully');
    closeModal('editUserModal');
    loadUsers();
  } catch (err) {
    console.error('Update user error:', err);
    showError(err.message || 'Failed to update user');
    showMessage('editUserMessage', err.message, true);
  }
}

// Reset Password Modal
function openResetPasswordModal(userId) {
  const user = allUsers.find(u => u.id === userId);
  if (!user) return;

  document.getElementById('resetUserId').value = user.id;
  document.getElementById('resetUsername').value = user.username;
  document.getElementById('resetNewPassword').value = '';
  document.getElementById('resetRequireChange').checked = false;

  openModal('resetPasswordModal');
}

async function resetPassword(userId, newPassword, requireChange) {
  try {
    const response = await authenticatedFetch(`/api/users/${userId}/password`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ newPassword, requireChange })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to reset password');
    }

    showSuccess('Password reset successfully');
    closeModal('resetPasswordModal');
  } catch (err) {
    console.error('Reset password error:', err);
    showError(err.message || 'Failed to reset password');
    showMessage('resetPasswordMessage', err.message, true);
  }
}

// Delete User Modal
function openDeleteModal(userId) {
  const user = allUsers.find(u => u.id === userId);
  if (!user) return;

  document.getElementById('deleteUserId').value = user.id;
  document.getElementById('deleteUserText').textContent =
    `Are you sure you want to deactivate the user "${user.username}"?`;

  openModal('deleteUserModal');
}

async function deleteUser(userId) {
  try {
    const response = await authenticatedFetch(`/api/users/${userId}`, {
      method: 'DELETE'
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Failed to deactivate user');
    }

    showSuccess('User deactivated successfully');
    closeModal('deleteUserModal');
    loadUsers();
  } catch (err) {
    console.error('Delete user error:', err);
    showError(err.message || 'Failed to deactivate user');
    showMessage('deleteUserMessage', err.message, true);
  }
}

// Event Listeners Setup
function setupEventListeners() {
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

  // Logout button
  document.getElementById('logoutBtn').addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      await authenticatedFetch('/api/logout', { method: 'POST' });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      window.location.href = '/login';
    }
  });

  // Create User Modal
  document.getElementById('createUserBtn').addEventListener('click', openCreateModal);
  document.getElementById('closeCreateModal').addEventListener('click', () => closeModal('createUserModal'));
  document.getElementById('cancelCreateBtn').addEventListener('click', () => closeModal('createUserModal'));

  document.getElementById('createUserForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('createUsername').value.trim();
    const password = document.getElementById('createPassword').value;
    const displayName = document.getElementById('createDisplayName').value.trim() || null;
    const email = document.getElementById('createEmail').value.trim() || null;
    const role = document.getElementById('createRole').value;

    if (!username || !password || !role) {
      showMessage('createUserMessage', 'Please fill in all required fields', true);
      return;
    }

    if (username.includes(' ')) {
      showMessage('createUserMessage', 'Username cannot contain spaces', true);
      return;
    }

    if (password.length < 8) {
      showMessage('createUserMessage', 'Password must be at least 8 characters', true);
      return;
    }

    await createUser({ username, password, displayName, email, role });
  });

  // Edit User Modal
  document.getElementById('closeEditModal').addEventListener('click', () => closeModal('editUserModal'));
  document.getElementById('cancelEditBtn').addEventListener('click', () => closeModal('editUserModal'));

  document.getElementById('editUserForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const userId = parseInt(document.getElementById('editUserId').value);
    const displayName = document.getElementById('editDisplayName').value.trim() || null;
    const email = document.getElementById('editEmail').value.trim() || null;
    const role = document.getElementById('editRole').value;
    const isActive = document.getElementById('editActive').value === '1';

    if (!role) {
      showMessage('editUserMessage', 'Please select a role', true);
      return;
    }

    await updateUser(userId, { displayName, email, role, isActive });
  });

  // Reset Password Modal
  document.getElementById('closeResetModal').addEventListener('click', () => closeModal('resetPasswordModal'));
  document.getElementById('cancelResetBtn').addEventListener('click', () => closeModal('resetPasswordModal'));

  document.getElementById('resetPasswordForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const userId = parseInt(document.getElementById('resetUserId').value);
    const newPassword = document.getElementById('resetNewPassword').value;
    const requireChange = document.getElementById('resetRequireChange').checked;

    if (newPassword.length < 8) {
      showMessage('resetPasswordMessage', 'Password must be at least 8 characters', true);
      return;
    }

    await resetPassword(userId, newPassword, requireChange);
  });

  // Delete User Modal
  document.getElementById('closeDeleteModal').addEventListener('click', () => closeModal('deleteUserModal'));
  document.getElementById('cancelDeleteBtn').addEventListener('click', () => closeModal('deleteUserModal'));

  document.getElementById('confirmDeleteBtn').addEventListener('click', async () => {
    const userId = parseInt(document.getElementById('deleteUserId').value);
    await deleteUser(userId);
  });

  // Close modals on background click
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeModal(modal.id);
      }
    });
  });
}

// Initialize
async function init() {
  const authenticated = await checkAuth();
  if (!authenticated) return;

  await fetchCsrfToken();
  await loadUsers();

  setupEventListeners();
}

// Start when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
