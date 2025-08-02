// Sistema de navegacion por modulos

console.log('TEST INICIAL - app.js cargado');

// Estado global de la aplicacion
let currentModule = 'otp';
let currentSection = 'otp-encrypt';
let learningProgress = {
    completed: ['basics'],
    current: 'hash-functions',
    available: ['basics', 'hash-functions'],
    locked: ['public-key', 'signatures', 'pow']
};

// Configuracion de modulos
const moduleConfig = {
    'otp': {
        name: 'One-Time Pad',
        color: '#28a745',
        sections: ['otp-encrypt', 'otp-break', 'otp-learn'],
        defaultSection: 'otp-encrypt'
    },
    'aes': {
        name: 'AES Encryption',
        color: '#007bff',
        sections: ['aes-encrypt', 'aes-modes'],
        defaultSection: 'aes-encrypt',
        disabled: true
    },
    'rsa': {
        name: 'RSA Cryptography',
        color: '#fd7e14',
        sections: ['rsa-keygen', 'rsa-sign', 'rsa-verify'],
        defaultSection: 'rsa-keygen',
        disabled: true
    },
    'hash': {
        name: 'Hash Functions',
        color: '#6f42c1',
        sections: ['sha256-hash', 'merkle-trees'],
        defaultSection: 'sha256-hash'
    },
    'pow': {
        name: 'Proof of Work',
        color: '#dc3545',
        sections: ['mining-simulation', 'difficulty-adjust'],
        defaultSection: 'mining-simulation',
        disabled: true
    }
};

// Inicializar aplicacion
document.addEventListener('DOMContentLoaded', function() {
    console.log('INICIANDO CryptoToolkit-Go...');

    const moduleCards = document.querySelectorAll('.module-card');
    console.log('Modulos encontrados:', moduleCards.length);

    const progressItems = document.querySelectorAll('.progress-item');
    console.log('Progress items encontrados:', progressItems.length);

    initializeModuleNavigation();
    initializeLearningPath();
    initializeButtonHandlers();
    selectModule('otp');

    console.log('INICIALIZACION COMPLETA');
});

function initializeButtonHandlers() {
    console.log('Inicializando manejadores de botones...');

    document.addEventListener('click', function(event) {
        const target = event.target;

        if (target.dataset.action) {
            event.preventDefault();
            const action = target.dataset.action;
            const moduleCard = target.closest('.module-card');
            const moduleKey = moduleCard ? moduleCard.dataset.module : null;

            console.log('Accion:', action, 'en modulo:', moduleKey);

            if (moduleKey && moduleKey !== currentModule) {
                selectModule(moduleKey);
            }

            handleButtonAction(action, moduleKey);
        }
    });
}

function handleButtonAction(action, moduleKey) {
    console.log('Ejecutando accion:', action);

    switch(action) {
        case 'encrypt':
            if (moduleKey === 'otp') {
                showSection('otp-section');
            }
            break;

        case 'execute-encrypt':
            if (currentModule === 'otp') {
                encryptOTP();
            }
            break;

        case 'break':
            if (moduleKey === 'otp') {
                showSection('otp-section');
                alert('Demo: Key reuse vulnerability demonstration');
            }
            break;

        case 'learn':
            alert('Learning module: Conceptos fundamentales de criptografia');
            break;

        case 'sha256':
            if (moduleKey === 'hash') {
                showSection('sha256-section');
            }
            break;

        case 'execute-sha256':
            if (currentModule === 'hash') {
                hashSHA256();
            }
            break;

        default:
            console.log('Accion no reconocida:', action);
    }
}

function initializeModuleNavigation() {
    console.log('Inicializando navegacion por modulos...');

    const moduleCards = document.querySelectorAll('.module-card');
    moduleCards.forEach((card, index) => {
        const moduleKey = Object.keys(moduleConfig)[index];
        const config = moduleConfig[moduleKey];

        if (!config.disabled) {
            card.addEventListener('click', () => selectModule(moduleKey));
            card.style.cursor = 'pointer';
        }

        card.style.borderLeft = '4px solid ' + config.color;
    });
}

function selectModule(moduleKey) {
    const config = moduleConfig[moduleKey];
    if (!config || config.disabled) {
        console.log('Modulo no disponible:', moduleKey);
        return;
    }

    console.log('Cambiando a modulo:', config.name);

    currentModule = moduleKey;
    currentSection = config.defaultSection;

    updateModuleColors(moduleKey);
    showModuleInterface(moduleKey);

    console.log('Modulo activado:', config.name);
}

function updateModuleColors(activeModuleKey) {
    const moduleCards = document.querySelectorAll('.module-card');

    moduleCards.forEach((card, index) => {
        const moduleKey = Object.keys(moduleConfig)[index];
        const config = moduleConfig[moduleKey];

        card.classList.remove('active');

        if (moduleKey === activeModuleKey) {
            card.classList.add('active');
            card.style.backgroundColor = config.color + '20';
            card.style.borderColor = config.color;
            card.style.borderWidth = '2px';
            card.style.transform = 'translateX(5px)';
        } else {
            card.style.backgroundColor = 'transparent';
            card.style.borderColor = config.color + '40';
            card.style.borderWidth = '1px';
            card.style.transform = 'translateX(0)';
        }
    });
}

function showModuleInterface(moduleKey) {
    const allSections = document.querySelectorAll('.crypto-section');
    allSections.forEach(section => {
        section.classList.remove('active');
        section.style.display = 'none';
    });

    const config = moduleConfig[moduleKey];
    const targetSection = config.defaultSection;

    let sectionElement = document.getElementById(targetSection + '-section');

    if (!sectionElement) {
        const sectionMap = {
            'otp-encrypt': 'otp-section',
            'sha256-hash': 'sha256-section'
        };
        sectionElement = document.getElementById(sectionMap[targetSection]);
    }

    if (sectionElement) {
        sectionElement.classList.add('active');
        sectionElement.style.display = 'block';
        console.log('Mostrando interfaz:', targetSection);
    } else {
        console.warn('Seccion no encontrada:', targetSection);
    }
}

function initializeLearningPath() {
    console.log('Inicializando Learning Path...');

    const progressItems = document.querySelectorAll('.progress-item');
    progressItems.forEach((item) => {
        const stepName = item.querySelector('span:last-child').textContent.toLowerCase();
        const stepKey = stepName.replace(/\\s+/g, '-');

        item.addEventListener('click', () => handleLearningPathClick(stepKey, item));
        item.style.cursor = 'pointer';

        updateProgressItemStyle(item, stepKey);
    });
}

function handleLearningPathClick(stepKey, element) {
    const stepModuleMap = {
        'crypto-basics': 'otp',
        'hash-functions': 'hash',
        'public-key-crypto': 'rsa',
        'digital-signatures': 'rsa',
        'proof-of-work': 'pow'
    };

    const targetModule = stepModuleMap[stepKey];
    console.log('Learning Path:', stepKey, 'hacia', targetModule);

    if (learningProgress.available.includes(stepKey) || learningProgress.completed.includes(stepKey)) {
        selectModule(targetModule);
    } else {
        showLearningMessage(stepKey);
    }
}

function updateProgressItemStyle(item, stepKey) {
    const icon = item.querySelector('.progress-icon');

    if (learningProgress.completed.includes(stepKey)) {
        item.className = 'progress-item completed';
        icon.textContent = '✓';
        icon.style.color = '#28a745';
    } else if (learningProgress.current === stepKey) {
        item.className = 'progress-item current';
        icon.textContent = '→';
        icon.style.color = '#007bff';
    } else if (learningProgress.available.includes(stepKey)) {
        item.className = 'progress-item available';
        icon.textContent = '○';
        icon.style.color = '#6c757d';
        item.style.cursor = 'pointer';
    } else {
        item.className = 'progress-item locked';
        icon.textContent = '🔒';
        icon.style.color = '#dc3545';
        item.style.opacity = '0.5';
    }
}

function showLearningMessage(stepKey) {
    const messages = {
        'public-key-crypto': 'Completa Hash Functions para desbloquear Public Key Crypto',
        'digital-signatures': 'Completa Public Key Crypto para desbloquear Digital Signatures',
        'proof-of-work': 'Completa Digital Signatures para desbloquear Proof of Work'
    };

    alert(messages[stepKey] || 'Este paso aun no esta disponible');
}

function showSection(sectionId) {
    const sections = document.querySelectorAll('.crypto-section');
    sections.forEach(section => {
        section.classList.remove('active');
        section.style.display = 'none';
    });

    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
        targetSection.style.display = 'block';
        currentSection = sectionId;
    }
}

async function makeAPIRequest(endpoint, data) {
    try {
        const response = await fetch('/api/v1' + endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error('HTTP error! status: ' + response.status);
        }

        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

async function encryptOTP() {
    const message = document.getElementById('otp-message').value;
    const explain = document.getElementById('otp-explain').checked;

    if (!message.trim()) {
        alert('Please enter a message to encrypt');
        return;
    }

    try {
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
    }
}

function displayOTPResults(response) {
    const resultsArea = document.getElementById('otp-results');
    resultsArea.style.display = 'block';

    document.getElementById('otp-original').textContent = response.message;
    document.getElementById('otp-key').textContent = response.key;
    document.getElementById('otp-cipher').textContent = response.ciphertext;

    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('otp-steps');
        const stepsList = document.getElementById('otp-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = 'Step ' + step.step + ': ' + step.operation;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    }

    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

async function hashSHA256() {
    const input = document.getElementById('sha256-input').value;
    const explain = document.getElementById('sha256-explain').checked;

    if (!input.trim()) {
        alert('Please enter text to hash');
        return;
    }

    try {
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
    }
}

function displaySHA256Results(response) {
    const resultsArea = document.getElementById('sha256-results');
    resultsArea.style.display = 'block';

    document.getElementById('sha256-original').textContent = response.input;
    document.getElementById('sha256-hash').textContent = response.hash;

    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

async function demonstrateKeyReuse() {
    const message1 = document.getElementById('break-msg1').value;
    const message2 = document.getElementById('break-msg2').value;

    if (!message1.trim() || !message2.trim()) {
        alert('Please enter both messages');
        return;
    }

    try {
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
    }
}

function displayKeyReuseResults(response) {
    const resultsArea = document.getElementById('break-results');
    resultsArea.style.display = 'block';

    document.getElementById('break-original1').textContent = response.message1;
    document.getElementById('break-original2').textContent = response.message2;
    document.getElementById('break-cipher1').textContent = response.cipher1;
    document.getElementById('break-cipher2').textContent = response.cipher2;
    document.getElementById('break-xor').textContent = response.xorResult;
    document.getElementById('break-revealed').textContent = response.revealed || 'Information leaked!';

    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

console.log('TEST FINAL - app.js completado');
