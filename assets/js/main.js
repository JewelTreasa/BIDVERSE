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

    if (isAuthenticated && userData) {
        if (navButtons) {
            navButtons.innerHTML = `
                <span class="user-greeting">Welcome, ${userData.display_name || userData.email}!</span>
                <button onclick="logout()" class="btn btn-outline">Log Out</button>
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

// Logout function
window.logout = () => {
    // Redirect to our logout URL
    window.location.href = '/logout/';
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    checkAuthStatus();
});
