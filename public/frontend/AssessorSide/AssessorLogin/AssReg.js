document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const submitBtn = document.querySelector("#registerForm button[type='submit']");
  submitBtn.disabled = true;
  submitBtn.textContent = "Registering...";

  // Get form values
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirm-password").value;
  const fullName = document.getElementById("full-name").value;
  const expertise = document.getElementById("expertise").value;
  const assessorType = document.querySelector('input[name="assessor-type"]:checked')?.value;

  // Validation
  if (password !== confirmPassword) {
    alert("Error: Passwords do not match");
    submitBtn.disabled = false;
    submitBtn.textContent = "Register";
    return;
  }

  if (!email || !password || !fullName || !expertise || !assessorType) {
    alert("Error: All fields are required");
    submitBtn.disabled = false;
    submitBtn.textContent = "Register";
    return;
  }

  try {
    const response = await fetch("http://localhost:3000/assessor/register", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        password,
        fullName,
        expertise,
        assessorType
      }),
      credentials: 'include' // Important for cookies if you're using them
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Registration failed");
    }

    alert(`Success! Assessor ID: ${data.data.assessorId}\nPlease wait for admin approval.`);
    window.location.href = "/frontend/AssessorSide/AssessorLogin/AssessorLogin.html";

  } catch (error) {
    console.error("Registration error:", error);
    alert(`Error: ${error.message}`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Register";
  }
});