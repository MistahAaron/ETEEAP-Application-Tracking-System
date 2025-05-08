document.addEventListener("DOMContentLoaded", () => {
    // File upload handling
    const fileInput = document.getElementById("file-upload");
    const dropArea = document.querySelector(".upload");
    const fileList = document.getElementById("file-list");
    let uploadedFiles = new Set(); // Track unique files

    // Handle file selection and drops
    function handleFiles(files) {
        if (files.length === 0) return;

        Array.from(files).forEach(file => {
            // Validate file size
            if (file.size > 25 * 1024 * 1024) {
                showAlert(`File "${file.name}" exceeds the 25MB limit.`, 'error');
                return;
            }

            // Check for duplicate files
            if (uploadedFiles.has(file.name)) {
                showAlert(`File "${file.name}" is already uploaded.`, 'warning');
                return;
            }

            uploadedFiles.add(file.name);

            // Create file item element
            const fileItem = document.createElement("div");
            fileItem.classList.add("file-item");

            const fileName = document.createElement("p");
            fileName.classList.add("file-name");
            fileName.textContent = file.name;

            // Create remove button
            const removeButton = document.createElement("button");
            removeButton.textContent = "×";
            removeButton.classList.add("remove-btn");
            removeButton.title = "Remove file";

            // Remove file handler
            removeButton.onclick = function() {
                fileItem.remove();
                uploadedFiles.delete(file.name);
                updateFileCount();
            };

            // Add preview for images
            if (file.type.startsWith("image/")) {
                const filePreview = document.createElement("img");
                filePreview.classList.add("file-preview");
                filePreview.src = URL.createObjectURL(file);
                fileItem.appendChild(filePreview);
            }

            fileItem.appendChild(fileName);
            fileItem.appendChild(removeButton);
            fileList.appendChild(fileItem);

            updateFileCount();
        });
    }

    // Update the file counter display
    function updateFileCount() {
        const counter = document.getElementById("file-count");
        if (counter) {
            counter.textContent = `${uploadedFiles.size} file(s) selected`;
        }
    }

    // Show alert message
    function showAlert(message, type = 'info') {
        const alertBox = document.createElement("div");
        alertBox.className = `alert ${type}`;
        alertBox.textContent = message;
        
        document.body.appendChild(alertBox);
        
        setTimeout(() => {
            alertBox.classList.add('fade-out');
            setTimeout(() => alertBox.remove(), 500);
        }, 3000);
    }

    // File input change event
    fileInput.addEventListener("change", function() {
        handleFiles(this.files);
        this.value = ''; // Reset to allow selecting same file again
    });

    // Drag and drop events
    ["dragenter", "dragover"].forEach(event => {
        dropArea.addEventListener(event, (e) => {
            e.preventDefault();
            dropArea.classList.add("drag-active");
        });
    });

    ["dragleave", "drop"].forEach(event => {
        dropArea.addEventListener(event, (e) => {
            e.preventDefault();
            dropArea.classList.remove("drag-active");
        });
    });

    dropArea.addEventListener("drop", (e) => {
        handleFiles(e.dataTransfer.files);
    });

    // Prevent file manager from opening twice
    dropArea.addEventListener("click", (e) => {
        if (e.target === dropArea) {
            fileInput.click();
        }
    });

    // Course selection dropdown logic
    function updateDropdowns() {
        let selectedValues = new Set();

        // Get selected values from all dropdowns
        document.querySelectorAll("select").forEach(select => {
            if (select.value) {
                selectedValues.add(select.value);
            }
        });

        // Enable all options first
        document.querySelectorAll("select option").forEach(option => {
            option.hidden = false;
        });

        // Disable already selected options in other dropdowns
        document.querySelectorAll("select").forEach(select => {
            let selected = select.value;
            select.querySelectorAll("option").forEach(option => {
                if (selectedValues.has(option.value) && option.value !== selected) {
                    option.hidden = true;
                }
            });
        });
    }

    // Initialize dropdown change listeners
    document.querySelectorAll("select").forEach(select => {
        select.addEventListener("change", updateDropdowns);
    });

    // Initialize International Telephone Input
    const phoneInput = document.querySelector("#mobile-number");
    if (phoneInput) {
        const iti = window.intlTelInput(phoneInput, {
            initialCountry: "auto",
            geoIpLookup: function(callback) {
                fetch('https://ipinfo.io/json?token=YOUR_TOKEN')
                    .then(response => response.json())
                    .then(data => callback(data.country))
                    .catch(() => callback("us"));
            },
            utilsScript: "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.13/js/utils.js",
            nationalMode: false,
            separateDialCode: true,
            preferredCountries: ['ph', 'us', 'gb'],
            customPlaceholder: function(selectedCountryPlaceholder, selectedCountryData) {
                return "e.g. " + selectedCountryPlaceholder;
            }
        });

        // Add validation on blur
        phoneInput.addEventListener('blur', function() {
            if (phoneInput.value.trim()) {
                if (!iti.isValidNumber()) {
                    phoneInput.classList.add('error');
                    showAlert('Please enter a valid phone number', 'error');
                } else {
                    phoneInput.classList.remove('error');
                }
            }
        });
    }

    // Form submission handler
    const personalForm = document.getElementById("personalForm");
    if (personalForm) {
        personalForm.addEventListener("submit", async (event) => {
            event.preventDefault();

            // Validate required fields
            const requiredFields = [
                'firstname', 'lastname', 'gender', 'age', 'occupation',
                'nationality', 'civilstatus', 'birth-date', 'birthplace',
                'mobile-number', 'email-address', 'country', 'province',
                'city', 'street', 'zip-code', 'First-prio'
            ];

            let isValid = true;
            requiredFields.forEach(fieldId => {
                const field = document.getElementById(fieldId);
                if (!field || !field.value.trim()) {
                    if (field) field.classList.add('error');
                    isValid = false;
                } else {
                    if (field) field.classList.remove('error');
                }
            });

            if (!isValid) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }

            const userId = localStorage.getItem("userId");
            if (!userId) {
                showAlert('Session expired. Please login again.', 'error');
                setTimeout(() => {
                    window.location.href = '/frontend/Applicant/Login/login.html';
                }, 2000);
                return;
            }

            // Prepare personal info data
            const personalInfo = {
                firstname: document.getElementById("firstname").value.trim(),
                middlename: document.getElementById("middlename").value.trim(),
                lastname: document.getElementById("lastname").value.trim(),
                suffix: document.getElementById("suffix").value.trim(),
                gender: document.getElementById("gender").value,
                age: parseInt(document.getElementById("age").value) || 0,
                occupation: document.getElementById("occupation").value.trim(),
                nationality: document.getElementById("nationality").value.trim(),
                civilstatus: document.getElementById("civilstatus").value,
                birthDate: document.getElementById("birth-date").value,
                birthplace: document.getElementById("birthplace").value.trim(),
                mobileNumber: document.getElementById("mobile-number").value.trim(),
                telephoneNumber: document.getElementById("telephone-number").value.trim(),
                emailAddress: document.getElementById("email-address").value.trim(),
                country: document.getElementById("country").value.trim(),
                province: document.getElementById("province").value.trim(),
                city: document.getElementById("city").value.trim(),
                street: document.getElementById("street").value.trim(),
                zipCode: document.getElementById("zip-code").value.trim(),
                firstPriorityCourse: document.getElementById("First-prio").value,
                secondPriorityCourse: document.getElementById("second-prio").value,
                thirdPriorityCourse: document.getElementById("third-prio").value
            };

            // Prepare form data
            const formData = new FormData();
            formData.append("userId", userId);
            formData.append("personalInfo", JSON.stringify(personalInfo));

            // Add files if any
            if (fileInput.files.length > 0) {
                for (let i = 0; i < fileInput.files.length; i++) {
                    formData.append("files", fileInput.files[i]);
                }
            }

            try {
                // Update UI for submission
                const submitButton = personalForm.querySelector('button[type="submit"]');
                submitButton.disabled = true;
                submitButton.innerHTML = '<span class="spinner"></span> Submitting...';

                // Send data to server
                const response = await fetch("/api/update-personal-info", {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || "Failed to update information");
                }

                // Show success and redirect
                showAlert('Information submitted successfully!', 'success');
                setTimeout(() => {
                    window.location.href = "/frontend/Applicant/Login/login.html";
                }, 1500);

            } catch (error) {
                console.error("Submission error:", error);
                showAlert(`Error: ${error.message}`, 'error');
            } finally {
                const submitButton = personalForm.querySelector('button[type="submit"]');
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.textContent = "Submit";
                }
            }
        });
    }

    // Input validation styling
    const requiredFields = [
        'firstname', 'lastname', 'gender', 'age', 'occupation',
        'nationality', 'civilstatus', 'birth-date', 'birthplace',
        'mobile-number', 'email-address', 'country', 'province',
        'city', 'street', 'zip-code', 'First-prio'
    ];

    requiredFields.forEach(fieldId => {
        const field = document.getElementById(fieldId);
        if (field) {
            field.addEventListener('input', () => {
                if (field.value.trim()) {
                    field.classList.remove('error');
                }
            });
        }
    });

    // Date picker initialization
    const birthDateInput = document.getElementById("birth-date");
    if (birthDateInput) {
        birthDateInput.max = new Date().toISOString().split("T")[0];
    }

    // Age auto-calculation from birth date
    const ageInput = document.getElementById("age");
    if (birthDateInput && ageInput) {
        birthDateInput.addEventListener('change', function() {
            if (this.value) {
                const birthDate = new Date(this.value);
                const ageDiff = Date.now() - birthDate.getTime();
                const ageDate = new Date(ageDiff);
                const calculatedAge = Math.abs(ageDate.getUTCFullYear() - 1970);
                ageInput.value = calculatedAge;
            }
        });
    }
});

// CSS for dynamic elements (can be moved to stylesheet)
const dynamicStyles = `
    .alert {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        border-radius: 5px;
        color: white;
        z-index: 1000;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        transform: translateX(0);
        transition: all 0.3s ease;
    }
    .alert.info {
        background-color: #2196F3;
    }
    .alert.success {
        background-color: #4CAF50;
    }
    .alert.warning {
        background-color: #FF9800;
    }
    .alert.error {
        background-color: #F44336;
    }
    .alert.fade-out {
        transform: translateX(100%);
        opacity: 0;
    }
    .file-item {
        display: flex;
        align-items: center;
        padding: 8px 12px;
        margin: 5px 0;
        background: #f5f5f5;
        border-radius: 4px;
    }
    .file-preview {
        width: 40px;
        height: 40px;
        object-fit: cover;
        margin-right: 10px;
        border-radius: 3px;
    }
    .remove-btn {
        margin-left: auto;
        background: #ff4444;
        color: white;
        border: none;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .drag-active {
        border-color: #532989 !important;
        background-color: #f0e6ff !important;
    }
    .spinner {
        display: inline-block;
        width: 16px;
        height: 16px;
        border: 2px solid rgba(255,255,255,0.3);
        border-radius: 50%;
        border-top-color: white;
        animation: spin 1s ease-in-out infinite;
        margin-right: 8px;
    }
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    .error {
        border-color: #ff4444 !important;
    }
`;

// Add styles to the document
const styleElement = document.createElement("style");
styleElement.textContent = dynamicStyles;
document.head.appendChild(styleElement);