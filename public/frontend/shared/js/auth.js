// auth.js - Shared authentication functions for frontend

/**
 * Checks authentication status and redirects to login if not authenticated
 * Call this on any protected page
 */
async function protectPage() {
  try {
    const response = await fetch("http://localhost:3000/auth-status", { 
      credentials: "include" 
    });
    
    if (!response.ok) throw new Error("Not authenticated");
    
    const data = await response.json();

    if (!data.authenticated) {
      redirectToLogin();
    }
  } catch (error) {
    console.error("Error checking auth status", error);
    redirectToLogin();
  }
}

/**
 * Handles logout functionality
 */
async function handleLogout() {
  showLoading();
  try {
    // First verify authentication status
    const authCheck = await fetch('http://localhost:3000/auth-status', {
      credentials: 'include'
    });
    
    if (!authCheck.ok) {
      // If not authenticated, just redirect
      clearAuthData();
      redirectToLogin();
      return;
    }

    // If authenticated, proceed with logout
    const response = await fetch('http://localhost:3000/logout', {
      method: 'POST',
      credentials: 'include'
    });
    
    const data = await response.json();
    if (data.success) {
      showNotification('Logout successful! Redirecting...', 'success');
      clearAuthData();
      setTimeout(redirectToLogin, 1500);
    } else {
      showNotification('Logout failed. Please try again.', 'error');
      hideLoading();
    }
  } catch (error) {
    console.error('Logout error:', error);
    showNotification('Logout failed. Please try again.', 'error');
    hideLoading();
  }
}

/**
 * Redirects to login page
 */
function redirectToLogin() {
  // Check if we're already on login page to avoid infinite redirect
  if (!window.location.pathname.includes("login.html")) {
    window.location.href = '/frontend/ApplicantSide/ApplicantLogIn/login.html';
  }
}

/**
 * Clears all client-side authentication data
 */
function clearAuthData() {
  sessionStorage.removeItem('authData');
  localStorage.removeItem('authData');
}

/**
 * Shows loading spinner
 */
function showLoading() {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) spinner.classList.add("active");
}

/**
 * Hides loading spinner
 */
function hideLoading() {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) spinner.classList.remove("active");
}

/**
 * Shows notification message
 */
function showNotification(message, type = "info") {
  // Remove any existing notifications
  const existingNotifications = document.querySelectorAll(".notification");
  existingNotifications.forEach(notification => notification.remove());

  // Create new notification
  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.textContent = message;

  // Add notification to the document
  document.body.appendChild(notification);

  // Remove notification after delay
  setTimeout(() => {
    notification.style.opacity = "0";
    setTimeout(() => notification.remove(), 500);
  }, 3000);
}

/**
 * Initializes logout button if present
 */
function initializeLogout() {
  const logoutLink = document.getElementById('logoutLink');
  if (logoutLink) {
    logoutLink.addEventListener('click', async function(e) {
      e.preventDefault();
      await handleLogout();
    });
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  initializeLogout();
});

// Export functions if using modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    protectPage,
    handleLogout,
    showNotification,
    initializeLogout
  };
}


app.get("/assessor/auth-status", async (req, res) => {
  try {
      const token = req.cookies.assessorToken;
      if (!token) return res.json({ authenticated: false });

      const decoded = jwt.verify(token, JWT_SECRET);
      const assessor = await Assessor.findById(decoded.userId).select('-password');
      
      if (!assessor) {
          return res.json({ authenticated: false });
      }

      res.json({ 
          authenticated: true,
          user: {
              assessorId: assessor.assessorId,
              email: assessor.email,
              fullName: assessor.fullName
          }
      });
  } catch (err) {
      res.json({ authenticated: false });
  }
});