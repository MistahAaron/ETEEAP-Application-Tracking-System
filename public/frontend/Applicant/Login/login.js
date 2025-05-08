document.addEventListener("DOMContentLoaded", () => {
    const wrapper = document.querySelector('.wrapper');

    if (wrapper) {
        wrapper.classList.add('active-popup'); // Show login form immediately on page load
    }

    const buttons = {
        close: document.querySelector('.icon-close'),
        registerLink: document.querySelector('.register-link'),
        loginLink: document.querySelector('.login-link'),
        forgotLink: document.querySelector('.forgot-link')
    };

    // Save previous page URL before navigating to login
    if (document.referrer) {
        sessionStorage.setItem("previousPage", document.referrer);
    }

    // Function to reset input fields
    const resetInputs = () => {
        wrapper?.querySelectorAll('input').forEach(input => {
            if (input.type === 'checkbox') {
                input.checked = false;
            } else {
                input.value = '';
            }
        });
    };

    // Function to show different forms
    const showForm = (formType = '') => {
        wrapper?.classList.remove('active', 'active-forgot', 'active-verification', 'active-new-password');
        if (formType) wrapper?.classList.add(formType);
        resetInputs();
    };

    // Switch to Register Form
    buttons.registerLink?.addEventListener('click', (e) => {
        e.preventDefault();
        showForm('active'); // Show Register Form
    });

    // Switch back to Login Form
    buttons.loginLink?.addEventListener('click', (e) => {
        e.preventDefault();
        showForm(''); // Show Login Form
    });

    // Show Forgot Password Form
    buttons.forgotLink?.addEventListener('click', (e) => {
        e.preventDefault();
        showForm('active-forgot'); // Show Forgot Password Form
    });

    // Handle Reset Password Form Submission
    const resetForm = document.getElementById("resetForm");
    const verificationForm = document.getElementById("verificationForm");
    const newPasswordForm = document.getElementById("newPasswordForm");

    resetForm?.addEventListener("submit", (e) => {
        e.preventDefault();
        
        // Hide Forgot Password Form & Show Verification Form
        document.querySelector(".form-box.forgot").style.display = "none";
        verificationForm.style.display = "block";
        wrapper.classList.add("active-verification");
    });

    // Handle Verification Code Submission
    const verifyCodeForm = document.getElementById("verifyCodeForm");
    verifyCodeForm?.addEventListener("submit", (e) => {
        e.preventDefault();

        // Hide Verification Form & Show New Password Form
        verificationForm.style.display = "none";
        newPasswordForm.style.display = "block";
        wrapper.classList.add("active-new-password");
    });

    // Handle New Password Submission
    const newPasswordSubmit = document.getElementById("newPasswordSubmit");
    newPasswordSubmit?.addEventListener("submit", (e) => {
        e.preventDefault();

        const newPassword = document.getElementById("newPassword").value;
        const confirmPassword = document.getElementById("confirmPassword").value;

        if (newPassword !== confirmPassword) {
            showNotification("Passwords do not match. Please try again.");
            return;
        }

        showNotification("Password successfully reset! Redirecting to login page...");
        showForm(''); // Redirect to login form
    });

    document.querySelectorAll('.toggle-password').forEach(toggle => {
        toggle.addEventListener('click', () => {
            const input = toggle.parentElement.querySelector('input'); // Get correct input field
            const icon = toggle.querySelector('ion-icon'); // Get the ion-icon

            // Toggle password visibility
            if (input.type === "password") {
                input.type = "text";
                icon.setAttribute("name", "eye"); // Change icon to open eye
            } else {
                input.type = "password";
                icon.setAttribute("name", "eye-off"); // Change icon back to closed eye
            }
        });
    });
    
    // Handle Terms & Conditions
    document.getElementById("terms-link").addEventListener("click", function(event) {
        event.preventDefault(); // Prevent default link behavior
        document.getElementById("terms-con").style.display = "block"; // Show terms
    });
    
    // Close terms when clicking the "Accept" button and check the checkbox
    document.getElementById("accept-btn").addEventListener("click", function() {
        document.getElementById("terms-con").style.display = "none"; // Hide terms
        document.getElementById("terms-checkbox").checked = true; // Check the checkbox
    });
    

    // Close button handling: Return to previous page
    buttons.close?.addEventListener('click', () => {
        resetInputs();
        wrapper?.classList.remove('active-popup', 'active', 'active-forgot', 'active-verification', 'active-new-password');
        
        window.location.href = "../Home/index.html";
    });
});


// Registration Form Submission
document.getElementById("registerForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  
  const email = document.getElementById("regEmail").value.trim().toLowerCase();
  const password = document.getElementById("regPassword").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  // Client-side validation
  if (!email || !password || !confirmPassword) {
    showNotification("Please fill in all fields");
    return;
  }

  // Simple client-side email validation
  if (!email.includes('@') || !email.includes('.')) {
    showNotification("Please enter a valid email address (e.g., user@example.com)");
    return;
  }

  if (password !== confirmPassword) {
    showNotification("Passwords do not match!");
    return;
  }

  if (password.length < 8) {
    showNotification("Password must be at least 8 characters");
    return;
  }

  const submitBtn = event.target.querySelector('button[type="submit"]');
  const originalBtnText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.textContent = "Registering...";

  try {
    console.log("Attempting to register:", email);
    const response = await fetch("http://localhost:3000/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();
    console.log("Registration response:", data);

    if (!response.ok) {
      const errorMessage = data.details || data.error || "Registration failed";
      throw new Error(errorMessage);
    }

    showNotification("Registration successful! Please fill out your personal information.");
    localStorage.setItem("userId", data.data.userId);
    localStorage.setItem("applicantId", data.data.applicantId);
    window.location.href = "/frontend/Applicant/Information/information.html";
    
  } catch (error) {
    console.error("Registration error:", error);
    showNotification(`Registration failed: ${error.message}`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalBtnText;
  }
});

// Login Form Submission (single handler)
document.getElementById("loginForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  
  // Get form values
  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;

  if (!email || !password) {
    showNotification("Please enter both email and password.");
    return;
  }

  // Show loading state
  const submitBtn = event.target.querySelector('button[type="submit"]');
  const originalBtnText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.textContent = "Logging in...";

  try {
    const response = await fetch("http://localhost:3000/api/login", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ 
        email: email.trim().toLowerCase(), 
        password: password 
      }),
      credentials: 'include' // Important for cookies
    });

    const data = await response.json();

    if (response.ok) {
      showNotification("Login successful!");
      localStorage.setItem("userId", data.data.userId);
      localStorage.setItem("userEmail", data.data.email);
      window.location.href = "../Timeline/timeline.html";
    } else {
      throw new Error(data.error || "Login failed");
    }
  } catch (error) {
    console.error("Login error:", error);
    showNotification(`Login failed: ${error.message}`);
  } finally {
    // Reset button state
    submitBtn.disabled = false;
    submitBtn.textContent = originalBtnText;
  }
});


loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;

    if (!email || !password) {
        showNotification("Please enter both email and password.");
        return;
    }

    try {
        const response = await fetch("http://localhost:3000/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
          showNotification("Login successful!");
          localStorage.setItem("authToken", data.data.userId); // Note the nested structure
          localStorage.setItem("userId", data.data.userId);
          window.location.href = "../Timeline/timeline.html";
      } else {
            showNotification("Login failed: " + data.message);
        }
    } catch (error) {
        console.error("Error:", error);
        showNotification("An error occurred. Please try again.");
    }
});

function showNotification(message, type = "info") {
  const existingNotifications = document.querySelectorAll(".notification");
  existingNotifications.forEach(notification => notification.remove());

  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.textContent = message;
  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.opacity = "0";
    setTimeout(() => notification.remove(), 500);
  }, 3000);
}
