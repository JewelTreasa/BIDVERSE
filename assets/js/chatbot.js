/**
 * BidVerse Chatbot Logic
 * Handles UI interactions and communication with the backend
 */
document.addEventListener('DOMContentLoaded', () => {
    const fab = document.getElementById('chatbotFab');
    const window = document.getElementById('chatbotWindow');
    const closeBtn = window.querySelector('.fa-times');
    const input = document.getElementById('chatInput');
    const sendBtn = document.getElementById('chatSend');
    const messages = document.getElementById('chatMessages');
    const typing = document.getElementById('chatTyping');
    const clearBtn = document.getElementById('clearChat');
    const quickActionsContainer = document.getElementById('quickActions');

    // Role detection
    const isBuyer = window.classList.contains('role-buyer');
    const isSeller = window.classList.contains('role-seller');
    const isAdmin = window.classList.contains('role-admin');

    const roleActions = {
        buyer: ["Check my bids", "Active auctions", "Bidding help"],
        seller: ["My listings", "How to list", "Market trends", "Listing tips"],
        admin: ["Platform stats", "Pending users", "System health"],
        support: ["How it works", "Sessions", "Membership"]
    };

    // Toggle Window
    fab.addEventListener('click', () => {
        window.style.display = 'flex';
        if (messages.children.length === 0) {
            greet();
            renderQuickActions();
        }
    });

    function renderQuickActions() {
        if (!quickActionsContainer) return;
        quickActionsContainer.innerHTML = '';
        
        let actions = roleActions.support;
        if (isBuyer) actions = roleActions.buyer;
        else if (isSeller) actions = roleActions.seller;
        else if (isAdmin) actions = roleActions.admin;

        actions.forEach(action => {
            const btn = document.createElement('button');
            btn.className = 'action-btn';
            btn.textContent = action;
            btn.onclick = () => {
                input.value = action;
                sendMessage();
            };
            quickActionsContainer.appendChild(btn);
        });
    }

    function greet() {
        let name = "Support Bot";
        let role = "Platform Guide";
        
        if (isBuyer) { name = "Bid Bot"; role = "Bidding Assistant"; }
        else if (isSeller) { name = "Crop Bot"; role = "Listing Expert"; }
        else if (isAdmin) { name = "Shield Bot"; role = "System Monitor"; }

        addMessage(`Hi! I'm **${name}**, your **${role}**. How can I help you with BidVerse today?`, 'bot');
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (confirm('Are you sure you want to clear this chat session?')) {
                messages.innerHTML = '';
                greet();
                renderQuickActions();
            }
        });
    }

    closeBtn.addEventListener('click', () => {
        window.style.display = 'none';
    });

    // Send Message
    async function sendMessage() {
        const text = input.value.trim();
        if (!text) return;

        addMessage(text, 'user');
        input.value = '';
        
        // Show typing indicator
        typing.style.display = 'block';
        if (quickActionsContainer) quickActionsContainer.style.display = 'none'; // Hide while typing
        messages.scrollTop = messages.scrollHeight;

        try {
            const response = await fetch('/chatbot/message/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': window.CSRF_TOKEN || ''
                },
                body: JSON.stringify({ message: text })
            });

            const data = await response.json();
            typing.style.display = 'none';
            if (quickActionsContainer) quickActionsContainer.style.display = 'flex';

            if (data.response) {
                addMessage(data.response, 'bot');
            } else {
                addMessage("I'm sorry, I encountered an error. Please try again later.", 'bot');
            }
        } catch (error) {
            console.error('Chatbot error:', error);
            typing.style.display = 'none';
            if (quickActionsContainer) quickActionsContainer.style.display = 'flex';
            addMessage("Unable to connect to the assistant.", 'bot');
        }
    }

    function addMessage(text, sender) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${sender}`;
        
        // Escape HTML for safety, then apply simple markdown for bolding
        let safeText = text.replace(/&/g, '&amp;')
                           .replace(/</g, '&lt;')
                           .replace(/>/g, '&gt;')
                           .replace(/"/g, '&quot;')
                           .replace(/'/g, '&#039;');
        
        // Replace **bold** with <strong>bold</strong>
        const formattedText = safeText.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        
        msgDiv.innerHTML = formattedText;
        messages.appendChild(msgDiv);
        messages.scrollTop = messages.scrollHeight;
    }

    sendBtn.addEventListener('click', sendMessage);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
});
