// Main JavaScript file for BidVerse - Django Authentication

// Check if user is authenticated via Django session
function checkAuthStatus() {
    // Make a request to check authentication status
    fetch('/api/auth/check-auth/', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'same-origin' // Include cookies for session authentication
    })
    .then(response => response.json())
    .then(data => {
        updateAuthUI(data.authenticated, data.user);
    })
    .catch(error => {
        console.error('Auth check failed:', error);
        updateAuthUI(false, null);
    });
}

function updateAuthUI(isAuthenticated, userData) {
    const navButtons = document.querySelector('.nav-buttons');

    // Check if profile dropdown already exists (Django template rendered it)
    const existingProfileDropdown = navButtons?.querySelector('.profile-dropdown');
    
    if (existingProfileDropdown) {
        // Profile dropdown already exists from Django template, don't override
        return;
    }

    if (isAuthenticated && userData) {
        if (navButtons) {
            navButtons.innerHTML = `
                <div class="profile-dropdown" style="display: flex !important; align-items: center; position: relative;">
                    <button class="profile-icon-btn" onclick="toggleProfileDropdown()" aria-label="Profile" style="color: white !important; font-size: 1.8rem; cursor: pointer; background: transparent; border: none; padding: 0.5rem;">
                        <i class="fas fa-user-circle" style="color: white !important; display: block;"></i>
                    </button>
                    <div class="dropdown-menu" id="profileDropdown">
                        <div class="dropdown-header">
                            <span class="user-name">${userData.first_name || ''} ${userData.last_name || ''}</span>
                            <span class="user-email">${userData.email || ''}</span>
                        </div>
                        <a href="/dashboard/" class="dropdown-item">
                            <i class="fas fa-columns"></i> Dashboard
                        </a>
                        <a href="/logout/" class="dropdown-item">
                            <i class="fas fa-sign-out-alt"></i> Log Out
                        </a>
                    </div>
                </div>
            `;
        }
    } else {
        if (navButtons) {
            navButtons.innerHTML = `
                <a href="/login/" class="btn btn-outline">Log In</a>
                <a href="/register/" class="btn btn-primary">Get Started</a>
            `;
        }
    }
}

// Toggle profile dropdown function
window.toggleProfileDropdown = function() {
    const dropdown = document.getElementById('profileDropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
};

// Close dropdown when clicking outside
window.addEventListener('click', function(e) {
    const dropdown = document.getElementById('profileDropdown');
    const btn = document.querySelector('.profile-icon-btn');

    if (dropdown && dropdown.classList.contains('show')) {
        if (!dropdown.contains(e.target) && (!btn || !btn.contains(e.target))) {
            dropdown.classList.remove('show');
        }
    }
});

// Logout function
window.logout = () => {
    // Redirect to our logout URL
    window.location.href = '/logout/';
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Skip auth check on home page - Django template handles authentication
    if (window.location.pathname === '/' || window.location.pathname === '/home/') {
        console.log('Home page detected - Django template handles auth, skipping JavaScript override');
        return;
    }
    
    // Check if this is a Django template page - if nav-buttons has ANY content, Django template rendered it
    const navButtons = document.querySelector('.nav-buttons');
    if (!navButtons) {
        checkAuthStatus();
        return;
    }
    
    // If nav-buttons has any children, Django template already rendered it - don't override
    // This prevents JavaScript from replacing Django template content
    if (navButtons.children.length > 0 || navButtons.innerHTML.trim().length > 0) {
        console.log('Django template already rendered nav-buttons, skipping JavaScript override');
        return;
    }
    
    // Only run for pages that don't have Django template rendering (empty nav-buttons)
    checkAuthStatus();
});
