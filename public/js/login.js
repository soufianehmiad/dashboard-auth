document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const errorDiv = document.getElementById('error');
  const loginBtn = document.getElementById('loginBtn');
  
  // Clear previous errors
  errorDiv.classList.remove('show');
  errorDiv.textContent = '';
  
  // Disable button
  loginBtn.disabled = true;
  loginBtn.textContent = 'Signing in...';
  
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (response.ok && data.success) {
      // Small delay to ensure cookie is set
      setTimeout(() => {
        // Security: Check if password change is required
        if (data.passwordMustChange) {
          // Redirect to settings with a message parameter
          window.location.href = '/settings?passwordChangeRequired=true';
        } else {
          // Get return path from URL parameter, default to dashboard
          const urlParams = new URLSearchParams(window.location.search);
          const returnPath = urlParams.get('return') || '/';
          window.location.href = returnPath;
        }
      }, 100);
    } else {
      throw new Error(data.error || 'Login failed');
    }
  } catch (err) {
    errorDiv.textContent = err.message || 'Connection error. Please try again.';
    errorDiv.classList.add('show');
    loginBtn.disabled = false;
    loginBtn.textContent = 'Sign in';
    
    // Focus password field for retry
    document.getElementById('password').select();
  }
});

// Auto-focus username field
document.getElementById('username').focus();
