document.addEventListener("DOMContentLoaded", function () {
    const logoutButton = document.querySelector("#logout");

    if (logoutButton) {
        logoutButton.addEventListener("click", function (event) {
            event.preventDefault();

            //  Clear frontend session data
            sessionStorage.clear();
            localStorage.removeItem("userSession");

            //  Redirect to home page
            window.location.href = "../Login/login.html";
        });
    }

    const dropdownToggles = document.querySelectorAll(".dropdown-toggle");

    dropdownToggles.forEach((toggle) => {
        toggle.addEventListener("click", function (event) {
            event.preventDefault();
            const parentDropdown = toggle.parentElement;
            parentDropdown.classList.toggle("active");

            // Close other dropdowns
            document.querySelectorAll(".dropdown").forEach((dropdown) => {
                if (dropdown !== parentDropdown) {
                    dropdown.classList.remove("active");
                }
            });
        });
    });

    // Close dropdowns if clicked outside
    document.addEventListener("click", function (event) {
        if (!event.target.closest(".dropdown")) {
            document.querySelectorAll(".dropdown").forEach((dropdown) => {
                dropdown.classList.remove("active");
            });
        }
    });

    document.querySelectorAll(".top-section").forEach(section => {
        section.addEventListener("click", function () {
            document.querySelectorAll(".dropdown-section").forEach(otherSection => {
                if (otherSection !== this.closest(".dropdown-section")) {
                    otherSection.classList.remove("expanded");
                    otherSection.querySelector(".arrow").classList.remove("rotated");
                    otherSection.querySelector(".file-table").classList.add("hidden");
                    otherSection.querySelector(".upload-btn").classList.add("hidden");
                }
            });

            const parent = this.closest(".dropdown-section");
            parent.classList.toggle("expanded"); // Toggle expand class to control height
            parent.querySelector(".arrow").classList.toggle("rotated"); // Rotate arrow
            parent.querySelector(".file-table").classList.toggle("hidden");
            parent.querySelector(".upload-btn").classList.toggle("hidden");
        });
    });

    document.querySelectorAll(".upload-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            event.stopPropagation();
            this.closest(".dropdown-section").querySelector(".file-input").click();
        });
    });

    document.querySelectorAll(".file-input").forEach(input => {
        input.addEventListener("change", function () {
            const parent = this.closest(".dropdown-section");
            const fileTableBody = parent.querySelector(".file-table tbody");
            const fileCountSpan = parent.querySelector(".file-count");
            
            Array.from(this.files).forEach(file => {
                const documentId = Math.floor(Math.random() * 10000);
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td title="${file.name}">${file.name}</td>
                    <td>Uploaded</td>
                    <td>${new Date().toLocaleDateString()}</td>
                    <td>${documentId}</td>
                    <td>
                        <button class="view-btn" data-file-url="${URL.createObjectURL(file)}">View</button>
                        <button class="delete-btn">Delete</button>
                    </td>
                `;
                fileTableBody.appendChild(row);
            });
            fileCountSpan.textContent = fileTableBody.children.length;
            this.value = "";
        });
    });

    document.addEventListener("click", function (event) {
        if (event.target.classList.contains("delete-btn")) {
            const row = event.target.closest("tr");
            const parent = row.closest(".dropdown-section");
            row.remove();
            parent.querySelector(".file-count").textContent = parent.querySelector(".file-table tbody").children.length;
        }

        if (event.target.classList.contains("view-btn")) {
            const fileUrl = event.target.getAttribute("data-file-url");
            window.open(fileUrl, "_blank");
        }
    });

    const searchBar = document.querySelector(".search-bar");
    const clearSearchBtn = document.querySelector(".clear-search");

    // Show/hide the X icon based on input value
    searchBar.addEventListener("input", function () {
        const searchText = searchBar.value.toLowerCase();
        if (searchText.length > 0) {
            clearSearchBtn.style.display = "block"; // Show X icon
        } else {
            clearSearchBtn.style.display = "none"; // Hide X icon when the input is empty
        }

        document.querySelectorAll(".dropdown-section").forEach(section => {
            const fileRows = section.querySelectorAll("tbody tr");
            let fileMatch = false;

            fileRows.forEach(row => {
                const fileName = row.querySelector("td").textContent.toLowerCase();
                if (fileName.includes(searchText)) {
                    row.style.display = "table-row";
                    fileMatch = true;
                } else {
                    row.style.display = "none";
                }
            });

            if (fileMatch) {
                section.classList.add("expanded");
                section.querySelector(".arrow").classList.add("rotated");
                section.querySelector(".file-table").classList.remove("hidden");
                section.querySelector(".upload-btn").classList.remove("hidden");
            } else {
                section.classList.remove("expanded");
                section.querySelector(".arrow").classList.remove("rotated");
                section.querySelector(".file-table").classList.add("hidden");
                section.querySelector(".upload-btn").classList.add("hidden");
            }
        });
    });

    // Clear the search bar when the X icon is clicked
    clearSearchBtn.addEventListener("click", function () {
        searchBar.value = ""; // Clear the input
        clearSearchBtn.style.display = "none"; // Hide the X icon
        searchBar.dispatchEvent(new Event("input")); // Trigger input event to update file display
    });
});
