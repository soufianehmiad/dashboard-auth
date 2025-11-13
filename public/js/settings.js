let currentUser = null;

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
      currentUser = data;
      document.getElementById('username').textContent = data.displayName || data.username;
      // Set current display name in form
      document.getElementById('displayName').value = data.displayName || data.username;
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

function showMessage(messageId, text, isError = false) {
  const messageDiv = document.getElementById(messageId);
  messageDiv.textContent = text;
  messageDiv.style.display = 'block';
  messageDiv.style.padding = '12px';
  messageDiv.style.marginBottom = '16px';
  messageDiv.style.border = `1px solid ${isError ? '#f85149' : '#3fb950'}`;
  messageDiv.style.background = isError ? '#21161d' : '#0d1d17';
  messageDiv.style.color = isError ? '#f85149' : '#3fb950';
  messageDiv.style.fontSize = '14px';

  setTimeout(() => {
    messageDiv.style.display = 'none';
  }, 5000);
}

document.getElementById('changeDisplayNameForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const displayName = document.getElementById('displayName').value.trim();

  if (displayName.length < 2) {
    showMessage('nameMessage', 'Display name must be at least 2 characters', true);
    return;
  }

  try {
    const response = await fetch('/api/change-display-name', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ displayName })
    });

    const result = await response.json();

    if (!response.ok) {
      showMessage('nameMessage', result.error || 'Failed to update display name', true);
      return;
    }

    showMessage('nameMessage', 'Display name updated successfully!', false);
    // Update the username display in header
    document.getElementById('username').textContent = result.displayName;
  } catch (err) {
    console.error('Display name change error:', err);
    showMessage('nameMessage', 'Failed to update display name', true);
  }
});

document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const currentPassword = document.getElementById('currentPassword').value;
  const newPassword = document.getElementById('newPassword').value;
  const confirmPassword = document.getElementById('confirmPassword').value;

  if (newPassword !== confirmPassword) {
    showMessage('passwordMessage', 'New passwords do not match', true);
    return;
  }

  if (newPassword.length < 8) {
    showMessage('passwordMessage', 'Password must be at least 8 characters', true);
    return;
  }

  try {
    const response = await fetch('/api/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({
        currentPassword,
        newPassword
      })
    });

    const result = await response.json();

    if (!response.ok) {
      showMessage('passwordMessage', result.error || 'Failed to change password', true);
      return;
    }

    showMessage('passwordMessage', 'Password changed successfully!', false);
    document.getElementById('changePasswordForm').reset();
  } catch (err) {
    console.error('Password change error:', err);
    showMessage('passwordMessage', 'Failed to change password', true);
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

  // Security: Check if password change is required
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('passwordChangeRequired') === 'true') {
    showMessage('passwordMessage', 'SECURITY: You must change your password before continuing. The default password is not secure.', true);
    // Remove the parameter from URL without reloading
    window.history.replaceState({}, document.title, '/settings');
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
