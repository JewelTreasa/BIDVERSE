// Mobile Menu Toggle
const mobileBtn = document.querySelector('.mobile-menu-btn');
const navLinks = document.querySelector('.nav-links');
const navButtons = document.querySelector('.nav-buttons');

if (mobileBtn) {
    mobileBtn.addEventListener('click', () => {
        navLinks.classList.toggle('active');
        navButtons.classList.toggle('active');

        // Simple animation for the hamburger icon
        const icon = mobileBtn.querySelector('i');
        if (navLinks.classList.contains('active')) {
            icon.classList.remove('fa-bars');
            icon.classList.add('fa-times');

            // Add styles for mobile menu visibility
            Object.assign(navLinks.style, {
                display: 'flex',
                flexDirection: 'column',
                position: 'absolute',
                top: '100%',
                left: '0',
                width: '100%',
                backgroundColor: 'white',
                padding: '2rem',
                boxShadow: '0 4px 6px rgba(0,0,0,0.1)'
            });

            Object.assign(navButtons.style, {
                display: 'flex',
                flexDirection: 'column',
                position: 'absolute',
                top: 'calc(100% + 250px)', /* Approximate height of links */
                left: '0',
                width: '100%',
                backgroundColor: 'white',
                padding: '0 2rem 2rem',
                boxShadow: '0 4px 6px rgba(0,0,0,0.1)'
            });
        } else {
            icon.classList.add('fa-bars');
            icon.classList.remove('fa-times');
            navLinks.style.display = '';
            navButtons.style.display = '';
        }
    });
}

// Sticky Navbar Background on Scroll
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
        navbar.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1)';
    } else {
        navbar.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.05)';
    }
});

// Countdown Timer Logic
const timers = document.querySelectorAll('.timer');

timers.forEach(timer => {
    // Get the time string (e.g., "02:14:30")
    let timeStr = timer.innerText;
    let [hours, minutes, seconds] = timeStr.split(':').map(Number);

    // Convert to total seconds
    let totalSeconds = hours * 3600 + minutes * 60 + seconds;

    const interval = setInterval(() => {
        if (totalSeconds <= 0) {
            clearInterval(interval);
            timer.innerText = "EXPIRED";
            timer.classList.add('text-danger');
            return;
        }

        totalSeconds--;

        const h = Math.floor(totalSeconds / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = totalSeconds % 60;

        timer.innerText = `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    }, 1000);
});

// Profile Dropdown Toggle
window.toggleProfileDropdown = function () {
    const dropdown = document.getElementById('profileDropdown');
    const notifDropdown = document.getElementById('notificationDropdown');
    
    // Close notification dropdown if open
    if (notifDropdown && notifDropdown.classList.contains('show')) {
        notifDropdown.classList.remove('show');
    }
    
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
};

// Notification Dropdown Toggle
window.toggleNotificationDropdown = function() {
    const dropdown = document.getElementById('notificationDropdown');
    const profileDropdown = document.getElementById('profileDropdown');
    
    // Close profile dropdown if open
    if (profileDropdown && profileDropdown.classList.contains('show')) {
        profileDropdown.classList.remove('show');
    }
    
    if (dropdown) {
        dropdown.classList.toggle('show');
        if (dropdown.classList.contains('show')) {
            loadNotifications();
        }
    }
};

window.loadNotifications = function() {
    const list = document.getElementById('notification-list');
    if (!list) return;
    
    fetch('/notifications/')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                list.innerHTML = `<div style="padding: 1rem; text-align: center; color: #dc2626;">${data.error}</div>`;
                return;
            }
            
            const badge = document.getElementById('notif-badge');
            
            if (data.length === 0) {
                list.innerHTML = '<div style="padding: 1rem; text-align: center; color: #666;">No notifications</div>';
                if(badge) badge.style.display = 'none';
                return;
            }
            
            let hasUnread = false;
            let html = '';
            data.forEach(notif => {
                if (!notif.is_read) {
                    hasUnread = true;
                    // Check for WIN notification to show celebration
                    if (notif.notification_type === 'WIN') {
                        showWinCelebration(notif);
                    }
                }
                const bg = notif.is_read ? 'white' : '#f0fdf4';
                const time = new Date(notif.created_at).toLocaleString();
                html += `
                <div onclick="markRead(${notif.id}, this)" style="padding: 10px 15px; border-bottom: 1px solid #eee; background: ${bg}; cursor: pointer; transition: background 0.2s;">
                    <p style="margin: 0; font-size: 0.9rem; color: #333; ${!notif.is_read ? 'font-weight: 600;' : ''}">${notif.message}</p>
                    <span style="font-size: 0.75rem; color: #999;">${time}</span>
                </div>
                `;
            });
            list.innerHTML = html;
            
            if(badge) {
                if (hasUnread) {
                    badge.style.display = 'block';
                } else {
                    badge.style.display = 'none';
                }
            }
        })
        .catch(err => {
            console.error('Error loading notifications:', err);
            list.innerHTML = '<div style="padding: 1rem; text-align: center; color: #dc2626;">Failed to load</div>';
        });
};

window.markRead = function(id, element) {
    fetch(`/notifications/mark/${id}/`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                element.style.background = 'white';
                element.querySelector('p').style.fontWeight = 'normal';
                
                // Hide badge if no more unread (simplified check)
                // Ideally strictly check count, but for now we can rely on next load or simple logic
                // For better UX, we could decriment a counter, but re-fetching or hiding badge on next open is okay.
            }
        });
};

// Polling for notifications (simple badge check)
setInterval(() => {
    const badge = document.getElementById('notif-badge');
    if (badge) {
        // Optional: We could implement a lightweight "check count" endpoint to avoid full fetch
        // For now, let's not spam valid requests excessively.
        // Or we just re-use loadNotifications if we want live updates.
        // loadNotifications(); // Uncomment if real-time polling is desired
    }
}, 60000);

// Close dropdown when clicking outside
window.addEventListener('click', function (e) {
    const profileDropdown = document.getElementById('profileDropdown');
    const notifDropdown = document.getElementById('notificationDropdown');
    const profileBtn = document.querySelector('.profile-icon-btn[aria-label="Profile"]');
    const notifBtn = document.querySelector('.profile-icon-btn[aria-label="Notifications"]');

    if (profileDropdown && profileDropdown.classList.contains('show')) {
        if (!profileDropdown.contains(e.target) && (!profileBtn || !profileBtn.contains(e.target))) {
            profileDropdown.classList.remove('show');
        }
    }
    
    if (notifDropdown && notifDropdown.classList.contains('show')) {
        if (!notifDropdown.contains(e.target) && (!notifBtn || !notifBtn.contains(e.target))) {
            notifDropdown.classList.remove('show');
        }
    }
});

// Win Celebration Logic
window.showWinCelebration = function(notif) {
    const modal = document.getElementById('winCelebrationModal');
    const msg = document.getElementById('winMessage');
    if (!modal || !msg) return;

    msg.innerText = notif.message;
    modal.style.display = 'flex';
    
    // Trigger Confetti
    triggerConfetti();

    // Mark as read so it doesn't pop up again
    fetch(`/notifications/mark/${notif.id}/`);
};

window.closeWinCelebration = function() {
    const modal = document.getElementById('winCelebrationModal');
    if (modal) modal.style.display = 'none';
};

window.triggerConfetti = function() {
    if (typeof confetti === 'function') {
        const duration = 5 * 1000;
        const animationEnd = Date.now() + duration;
        const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 2000 };

        function randomInRange(min, max) {
            return Math.random() * (max - min) + min;
        }

        const interval = setInterval(function() {
            const timeLeft = animationEnd - Date.now();

            if (timeLeft <= 0) {
                return clearInterval(interval);
            }

            const particleCount = 50 * (timeLeft / duration);
            // since particles fall down, start a bit higher than random
            confetti({ ...defaults, particleCount, origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 } });
            confetti({ ...defaults, particleCount, origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 } });
        }, 250);
    } else {
        console.warn('Confetti library not loaded');
    }
};

// Initial notification load to check for wins on page load
if (document.getElementById('notif-badge')) {
    setTimeout(loadNotifications, 1000);
}

