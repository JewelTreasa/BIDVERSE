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
