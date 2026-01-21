(function() {
    const roleConfig = {
        BUYER: {
            name: "Bid Bot",
            role: "Bidding Assistant",
            greeting: "Welcome! I'm your Bidding Assistant. How can I help you today?",
            knowledge: [
                { keywords: ["bid", "how to"], response: "To place a bid, go to any live auction and enter your amount. It must be at least ₹1 higher than the current highest bid!" },
                { keywords: ["won", "win"], response: "When you win an auction, you'll receive a confirmation email and a 🏆 notification on your dashboard!" },
                { keywords: ["payment"], response: "Payments are settled after the auction ends. Your seller will provide details in the 'Orders' section." }
            ]
        },
        FARMER: {
            name: "Crop Bot",
            role: "Listing Expert",
            greeting: "Greetings, Farmer! I'm here to assist with your listings. What do you need help with?",
            knowledge: [
                { keywords: ["listing", "add"], response: "Click 'Add Listed' in your sidebar to create a new auction. Remember to upload high-quality photos to attract buyers!" },
                { keywords: ["sold", "payment"], response: "Once an item is sold, you can find the buyer's details and payment status in your 'Sales History'." }
            ]
        },
        ADMIN: {
            name: "Shield Bot",
            role: "System Monitor",
            greeting: "System Monitor online. How can I assist with administrative tasks today?",
            knowledge: [
                { keywords: ["verify", "user"], response: "To verify a user, go to 'User Management' and click the 'Verify' button next to their name." },
                { keywords: ["monitor", "live"], response: "The 'Monitor Auctions' section shows all real-time bidding activity across BidVerse." },
                { keywords: ["report"], response: "You can generate comprehensive sales and engagement reports in the 'Reports' section." }
            ]
        },
        SUPPORT: {
            name: "Support Bot",
            role: "Platform Guide",
            greeting: "Welcome to BidVerse! I'm your Platform Guide. How can I help you get started?",
            knowledge: [
                { keywords: ["register", "sign up"], response: "Click 'Get Started' to create an account as a Farmer or Buyer. It's quick and free!" },
                { keywords: ["login", "access"], response: "You can log in with your registered email and password on the login page." },
                { keywords: ["contact", "support"], response: "You can reach our help team through the 'Contact' page for any specific issues!" }
            ]
        }
    };

    function getSessionInfo() {
        const now = new Date();
        const hour = now.getHours();
        const minute = now.getMinutes();
        const totalMinutes = hour * 60 + minute;

        if (totalMinutes >= 570 && totalMinutes < 810) { // 9:30 AM - 1:30 PM
            return { name: "Morning Session", active: true, end: "1:30 PM" };
        } else if (totalMinutes >= 855 && totalMinutes < 1095) { // 2:15 PM - 6:15 PM
            return { name: "Evening Session", active: true, end: "6:15 PM" };
        }
        return { name: "Off-session", active: false, next: totalMinutes < 570 ? "9:30 AM" : "Tomorrow 9:30 AM" };
    }

    function initChatbot() {
        const userRole = document.body.dataset.userRole || 'SUPPORT';
        const config = roleConfig[userRole] || roleConfig.SUPPORT;
        const session = getSessionInfo();
        
        const fab = document.getElementById('chatbotFab');
        const window = document.getElementById('chatbotWindow');
        const list = document.getElementById('chatMessages');
        const input = document.getElementById('chatInput');
        const sendBtn = document.getElementById('chatSend');
        const typing = document.getElementById('chatTyping');
        const botNameEl = document.getElementById('botName');
        const botRoleEl = document.getElementById('botRole');

        if (!fab) return;

        // Sync UI with role
        if (botNameEl) botNameEl.innerText = config.name;
        if (botRoleEl) botRoleEl.innerText = config.role;

        // Open/Close
        fab.onclick = () => {
            const isVisible = window.style.display === 'flex';
            window.style.display = isVisible ? 'none' : 'flex';
            if (!isVisible && list.children.length === 0) {
                addMessage(config.greeting, 'bot');
            }
        };

        // Send Message
        function handleSend() {
            const text = input.value.trim();
            if (!text) return;

            addMessage(text, 'user');
            input.value = '';
            
            // Show typing
            typing.style.display = 'block';
            setTimeout(() => {
                typing.style.display = 'none';
                handleResponse(text);
            }, 800);
        }

        sendBtn.onclick = handleSend;
        input.onkeypress = (e) => { if (e.key === 'Enter') handleSend(); };

        function addMessage(text, side) {
            const div = document.createElement('div');
            div.className = `message ${side}`;
            div.innerText = text;
            list.appendChild(div);
            list.scrollTop = list.scrollHeight;
        }

        function handleResponse(text) {
            const query = text.toLowerCase();
            const session = getSessionInfo();
            let response = "";

            // Dynamic Session Check
            if (query.includes("session") || query.includes("time") || query.includes("when")) {
                if (session.active) {
                    response = `We are currently in the **${session.name}**, which ends at **${session.end}**.`;
                } else {
                    response = `We are currently off-session. The next auction starts at **${session.next}**.`;
                }
            } else {
                // Check Role-specific Knowledge
                for (const item of config.knowledge) {
                    if (item.keywords.some(k => query.includes(k))) {
                        response = item.response;
                        break;
                    }
                }
            }

            if (!response) {
                response = "I'm here to help with " + (userRole === 'FARMER' ? "listing crops and session times." : "bidding rules and session schedules.") + " Could you be more specific?";
            }
            
            addMessage(response, 'bot');
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initChatbot);
    } else {
        initChatbot();
    }
})();
