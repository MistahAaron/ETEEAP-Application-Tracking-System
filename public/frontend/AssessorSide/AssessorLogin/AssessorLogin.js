document.getElementById("assessorLoginForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  // Clear previous errors
  document.querySelectorAll('.error-message').forEach(el => el.remove());

  // Get form values
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  // Validate input
  if (!email || !password) {
    showError("email", "Email and password are required");
    return;
  }

  // Disable button during request
  const submitBtn = event.target.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  
  try {
    const response = await fetch("http://localhost:3000/assessor/login", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
      credentials: "include"
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    // Store assessor data
    sessionStorage.setItem("assessorData", JSON.stringify({
      assessorId: data.data.assessorId,
      email: data.data.email,
      fullName: data.data.fullName
    }));

    // Redirect to dashboard using the frontend path
    window.location.href = data.redirectTo || "/frontend/AssessorSide/AssessorDashboard/AssessorDashboard.html";

  } catch (error) {
    console.error("Login error:", error);
    showError("email", error.message);
    alert(`Login failed: ${error.message}`);
  } finally {
    submitBtn.disabled = false;
  }
});

// Auth status check
document.addEventListener("DOMContentLoaded", async () => {
  if (window.location.pathname.includes("AssessorLogin")) {
    try {
      const response = await fetch("http://localhost:3000/assessor/auth-status", {
        credentials: "include"
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.authenticated) {
          window.location.href = "/frontend/AssessorSide/AssessorDashboard/AssessorDashboard.html";
        }
      }
    } catch (error) {
      console.log("Not logged in or error checking status:", error);
    }
  }
});

function showError(fieldId, message) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  
  const error = document.createElement('div');
  error.className = 'error-message';
  error.style.color = 'red';
  error.style.fontSize = '0.8rem';
  error.style.marginTop = '5px';
  error.textContent = message;
  field.insertAdjacentElement('afterend', error);
}