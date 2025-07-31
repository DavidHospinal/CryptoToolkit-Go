// Global state
let currentSection = 'otp-section';

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    showOTPEncrypt();
});

// Navigation handling
function initializeNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const section = this.dataset.section;
            if (section === 'playground') {
                // We're already in playground mode
                return;
            }
            // TODO: Implement other sections
        });
    });
}

// Show different crypto sections
function showOTPEncrypt() {
    showSection('otp-section');
    setActiveModule('otp-module');
}

function showOTPBreak() {
    showSection('otp-break-section');
    setActiveModule('otp-module');
}

function showOTPLearn() {
    // TODO: Implement learning section
    alert('Learning section coming soon!');
}

function showSHA256() {
    showSection('sha256-section');
    setActiveModule('hash-module');
}

function showSection(sectionId) {
    // Hide all sections
    const sections = document.querySelectorAll('.crypto-section');
    sections.forEach(section => {
        section.classList.remove('active');
    });

    // Show selected section
    document.getElementById(sectionId).classList.add('active');
    currentSection = sectionId;
}

function setActiveModule(moduleClass) {
    // Remove active class from all modules
    const modules = document.querySelectorAll('.module-card');
    modules.forEach(module => {
        module.classList.remove('active');
    });

    // Add active class to selected module
    document.querySelector('.' + moduleClass).classList.add('active');
}

// API Functions
async function makeAPIRequest(endpoint, data) {
    try {
        const response = await fetch(`/api/v1${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

// OTP Encryption
async function encryptOTP() {
    const message = document.getElementById('otp-message').value;
    const explain = document.getElementById('otp-explain').checked;

    if (!message.trim()) {
        alert('Please enter a message to encrypt');
        return;
    }

    try {
        // Show loading state
        const btn = event.target;
        const originalText = btn.textContent;
        btn.innerHTML = '<span class="loading"></span> Encrypting...';
        btn.disabled = true;

        const response = await makeAPIRequest('/otp/encrypt', {
            message: message,
            explain: explain
        });

        if (response.success) {
            displayOTPResults(response);
        } else {
            alert('Encryption failed: ' + (response.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Encryption failed: ' + error.message);
    } finally {
        // Reset button
        const btn = document.querySelector('#otp-section .btn-primary');
        btn.textContent = 'Encrypt Message';
        btn.disabled = false;
    }
}

function displayOTPResults(response) {
    // Show results area
    const resultsArea = document.getElementById('otp-results');
    resultsArea.style.display = 'block';

    // Fill in the results
    document.getElementById('otp-original').textContent = response.message;
    document.getElementById('otp-key').textContent = response.key;
    document.getElementById('otp-cipher').textContent = response.ciphertext;

    // Show steps if available
    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('otp-steps');
        const stepsList = document.getElementById('otp-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = `Step ${step.step}: ${step.operation}`;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    }

    // Scroll to results
    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

// OTP Key Reuse Demonstration
async function demonstrateKeyReuse() {
    const message1 = document.getElementById('break-msg1').value;
    const message2 = document.getElementById('break-msg2').value;

    if (!message1.trim() || !message2.trim()) {
        alert('Please enter both messages');
        return;
    }

    try {
        // Show loading state
        const btn = event.target;
        const originalText = btn.textContent;
        btn.innerHTML = '<span class="loading"></span> Demonstrating Attack...';
        btn.disabled = true;

        const response = await makeAPIRequest('/otp/demo-break', {
            message1: message1,
            message2: message2
        });

        if (response.success) {
            displayKeyReuseResults(response);
        } else {
            alert('Demonstration failed: ' + (response.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Demonstration failed: ' + error.message);
    } finally {
        // Reset button
        const btn = document.querySelector('#otp-break-section .btn-danger');
        btn.textContent = 'Demonstrate Attack';
        btn.disabled = false;
    }
}

function displayKeyReuseResults(response) {
    // Show results area
    const resultsArea = document.getElementById('break-results');
    resultsArea.style.display = 'block';

    // Fill in the results
    document.getElementById('break-original1').textContent = response.message1;
    document.getElementById('break-original2').textContent = response.message2;
    document.getElementById('break-cipher1').textContent = response.cipher1;
    document.getElementById('break-cipher2').textContent = response.cipher2;
    document.getElementById('break-xor').textContent = response.xorResult;
    document.getElementById('break-revealed').textContent = response.revealed || 'Information leaked!';

    // Scroll to results
    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

// SHA-256 Hashing
async function hashSHA256() {
    const input = document.getElementById('sha256-input').value;
    const explain = document.getElementById('sha256-explain').checked;

    if (!input.trim()) {
        alert('Please enter text to hash');
        return;
    }

    try {
        // Show loading state
        const btn = event.target;
        const originalText = btn.textContent;
        btn.innerHTML = '<span class="loading"></span> Calculating Hash...';
        btn.disabled = true;

        const response = await makeAPIRequest('/hash/sha256', {
            input: input,
            explain: explain
        });

        if (response.success) {
            displaySHA256Results(response);
        } else {
            alert('Hashing failed: ' + (response.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Hashing failed: ' + error.message);
    } finally {
        // Reset button
        const btn = document.querySelector('#sha256-section .btn-primary');
        btn.textContent = 'Calculate Hash';
        btn.disabled = false;
    }
}

function displaySHA256Results(response) {
    // Show results area
    const resultsArea = document.getElementById('sha256-results');
    resultsArea.style.display = 'block';

    // Fill in the results
    document.getElementById('sha256-original').textContent = response.input;
    document.getElementById('sha256-hash').textContent = response.hash;

    // Scroll to results
    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

// Utility functions
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        // Could add a toast notification here
        console.log('Copied to clipboard');
    });
}

// Add click-to-copy functionality to code elements
document.addEventListener('DOMContentLoaded', function() {
    const codeElements = document.querySelectorAll('code');
    codeElements.forEach(code => {
        code.addEventListener('click', function() {
            copyToClipboard(this.textContent);
        });
        code.style.cursor = 'pointer';
        code.title = 'Click to copy';
    });
});