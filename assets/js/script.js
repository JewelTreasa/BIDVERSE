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
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
};

// Close dropdown when clicking outside
window.addEventListener('click', function (e) {
    const dropdown = document.getElementById('profileDropdown');
    const btn = document.querySelector('.profile-icon-btn');

    if (dropdown && dropdown.classList.contains('show')) {
        if (!dropdown.contains(e.target) && (!btn || !btn.contains(e.target))) {
            dropdown.classList.remove('show');
        }
    }
});

// Smooth Scrolling for Anchor Links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();

        const targetId = this.getAttribute('href');
        if (targetId === '#') return;

        const targetElement = document.querySelector(targetId);

        if (targetElement) {
            // Close mobile menu if open
            if (navLinks.classList.contains('active')) {
                mobileBtn.click();
            }

            window.scrollTo({
                top: targetElement.offsetTop - 80, // Offset for sticky header
                behavior: 'smooth'
            });
        }
    });
});

// Live Auction Status Manager
function checkAuctionStatus() {
    const cards = document.querySelectorAll('.auction-card');
    const now = new Date();

    cards.forEach(card => {
        const startTimeStr = card.dataset.startTime;
        const endTimeStr = card.dataset.endTime;
        if (!startTimeStr) return;

        const startTime = new Date(startTimeStr);
        // Date comparison
        const isLive = now >= startTime;

        const liveBadge = card.querySelector('.badge.live');
        const upcomingBadge = card.querySelector('.badge.upcoming');
        const bidBtn = card.querySelector('.bid-btn');
        const notifyBtn = card.querySelector('.notify-btn');
        const bidLabel = card.querySelector('.bid-label');
        const timeLabel = card.querySelector('.time-label');
        const timeDisplay = card.querySelector('.auction-time');

        if (isLive) {
            // Switch to Live Mode
            if (liveBadge) liveBadge.style.display = '';
            if (upcomingBadge) upcomingBadge.style.display = 'none';
            if (bidBtn) bidBtn.style.display = '';
            if (notifyBtn) notifyBtn.style.display = 'none';

            if (bidLabel) bidLabel.innerText = 'Current Bid';
            if (timeLabel) timeLabel.innerText = 'Ends At';

            if (timeDisplay && endTimeStr) {
                const end = new Date(endTimeStr);
                const h = String(end.getHours()).padStart(2, '0');
                const m = String(end.getMinutes()).padStart(2, '0');
                timeDisplay.innerText = `${h}:${m}`;
            }
        } else {
            // Ensure Upcoming Mode
            if (liveBadge) liveBadge.style.display = 'none';
            if (upcomingBadge) upcomingBadge.style.display = '';
            if (bidBtn) bidBtn.style.display = 'none';
            if (notifyBtn) notifyBtn.style.display = '';

            if (bidLabel) bidLabel.innerText = 'Base Price';
            if (timeLabel) timeLabel.innerText = 'Starts At';

            if (timeDisplay && startTimeStr) {
                const start = new Date(startTimeStr);
                const h = String(start.getHours()).padStart(2, '0');
                const m = String(start.getMinutes()).padStart(2, '0');
                timeDisplay.innerText = `${h}:${m}`;
            }
        }
    });
}

// Run immediately and then every second
checkAuctionStatus();
setInterval(checkAuctionStatus, 1000);

// Notify Me Function
window.toggleNotify = function (btn, auctionId) {
    if ('Notification' in window && Notification.permission !== 'granted') {
        Notification.requestPermission();
    }

    // Toggle state
    if (btn.classList.contains('active')) {
        btn.classList.remove('active');
        btn.innerHTML = '<i class=\'far fa-bell\'></i> Notify Me';
        btn.style.background = '';
        btn.style.color = '';
    } else {
        btn.classList.add('active');
        btn.innerHTML = '<i class=\'fas fa-bell\'></i> Set';
        btn.style.background = '#f39c12';
        btn.style.color = 'white';
        alert('You will be notified when this auction starts!');
    }
};

