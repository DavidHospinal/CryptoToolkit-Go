// Sistema de navegacion por modulos

console.log('TEST INICIAL - app.js cargado');

// Estado global de la aplicacion
let currentModule = 'otp';
let currentSection = 'otp-encrypt';
let learningProgress = {
    completed: [],
    current: 'one-time-pad-(otp)',
    available: ['one-time-pad-(otp)'],
    locked: ['aes-encryption', 'rsa-cryptography', 'hash-functions', 'proof-of-work']
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
        disabled: false
    },
    'rsa': {
        name: 'RSA Cryptography',
        color: '#fd7e14',
        sections: ['rsa-keygen', 'rsa-sign', 'rsa-verify'],
        defaultSection: 'rsa-keygen',
        disabled: false
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
        disabled: false
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
    initializeHeaderNavigation(); // ✅ MOVER AQUÍ
    initializeAPIStatusCheck();   // ✅ MOVER AQUÍ
    selectModule('otp');

    console.log('INICIALIZACION COMPLETA'); // ✅ SOLO UNA VEZ
});

// NUEVA FUNCIÓN
function initializeHeaderNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const section = this.dataset.section;
            handleHeaderNavigation(section);
        });
    });
}

function handleHeaderNavigation(section) {
    switch(section) {
        case 'playground':
            // Ya estamos en playground - no hacer nada
            break;

        case 'tutorials':
            showTutorialsModal();
            break;

        case 'api-docs':
            showAPIDocsModal();
            break;

        case 'cli-guide':
            showCLIGuideModal();
            break;
    }
}

function showTutorialsModal() {
    const content = `📚 TUTORIALES DISPONIBLES

🔑 ONE-TIME PAD:
- Implementación paso a paso
- Casos de uso en criptografía militar
- Análisis de vulnerabilidades

🛡️ AES ENCRYPTION:
- Configuración de modos CBC/ECB/CTR
- Implementación en aplicaciones web
- Best practices de seguridad

🔐 RSA CRYPTOGRAPHY:
- Generación segura de claves
- Implementación de firmas digitales
- Protocolos de intercambio de claves

📊 HASH FUNCTIONS:
- Construcción de árboles de Merkle
- Implementación de blockchain simple
- Verificación de integridad

⛏️ PROOF OF WORK:
- Simulación de minado Bitcoin
- Algoritmos de ajuste de dificultad
- Análisis de consumo energético`;

    alert(content);
}

function showAPIDocsModal() {
    const content = `📖 DOCUMENTACIÓN API

BASE URL: http://localhost:8080/api/v1

🔑 ENDPOINTS OTP:
POST /otp/encrypt
POST /otp/demo-break

🛡️ ENDPOINTS AES:
POST /aes/encrypt

🔐 ENDPOINTS RSA:
POST /rsa/keygen
POST /rsa/sign
POST /rsa/verify

📊 ENDPOINTS HASH:
POST /hash/sha256
POST /hash/merkle
POST /hash/merkle-verify

⛏️ ENDPOINTS POW:
POST /pow/mine
POST /pow/difficulty

Consulta ejemplos de uso en cada módulo del playground.`;

    alert(content);
}

function showCLIGuideModal() {
    const content = `💻 GUÍA CLI

COMPILACIÓN:
go build -o cryptotoolkit cmd/api/main.go

EJECUCIÓN:
./cryptotoolkit --help

EJEMPLOS DE USO:
./cryptotoolkit otp encrypt "Hello World"
./cryptotoolkit aes encrypt --key="mykey" --data="secret"
./cryptotoolkit rsa keygen --size=2048
./cryptotoolkit hash sha256 "blockchain"
./cryptotoolkit pow mine --difficulty=4

OPCIONES GLOBALES:
--verbose    Mostrar información detallada
--output     Formato de salida (json, text)
--help       Mostrar ayuda

Nota: CLI en desarrollo - Actualmente solo disponible interfaz web.`;

    alert(content);
}
// Verificar estado API periódicamente
function initializeAPIStatusCheck() {
    checkAPIStatus(); // Verificación inicial
    setInterval(checkAPIStatus, 10000); // Cada 10 segundos
}

async function checkAPIStatus() {
    const statusIndicator = document.querySelector('.status-indicator');
    const statusText = document.querySelector('.api-status-text');

    try {
        const response = await fetch('/api/v1/health');
        if (response.ok) {
            statusIndicator.className = 'status-indicator online';
            statusText.textContent = 'API Online';
        } else {
            statusIndicator.className = 'status-indicator offline';
            statusText.textContent = 'API Error';
        }
    } catch (error) {
        statusIndicator.className = 'status-indicator offline';
        statusText.textContent = 'API Offline';
    }
}

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
                showSection('otp-break-section');
                //alert('Demo: Key reuse vulnerability demonstration');//
            }
            break;

        case 'learn':
            if (moduleKey === 'otp') {
                showOTPLearnContent();
            } else {
                alert(' Learning module: Conceptos fundamentales de criptografía');
            }
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
    //MANEJO DE ACCIONES AES
        case 'aes-encrypt':
            if (moduleKey === 'aes') {
                showSection('aes-section');
            }
            break;

        case 'execute-aes-encrypt':
            if (currentModule === 'aes') {
                encryptAES();
            }
            break;

        case 'aes-modes':
            alert('MODOS DE OPERACIÓN AES:\n\nCBC (Cipher Block Chaining):\n• Cifrado en cadena de bloques.\n• Seguro, requiere Vector de Inicialización (IV).\n• Uso: Cifrado de archivos y comunicaciones seguras.\n\nECB (Electronic Codebook):\n• Libro de códigos electrónico.\n• Simple pero inseguro (patrones visibles).\n• Uso: Solo para datos muy pequeños o claves.\n\nCTR (Counter Mode):\n• Modo contador, comportamiento de cifrado de flujo.\n• Permite paralelización y acceso aleatorio.\n• Uso: Cifrado de alta velocidad y streaming.');
            break;

        case 'aes-learn':
            showAESLearnContent();
            break;
        //MANEJO DE ACCIONES RSA
        case 'rsa-keygen':
            if (moduleKey === 'rsa') {
                showSection('rsa-section');
            }
            break;

        case 'execute-rsa-keygen':
            if (currentModule === 'rsa') {
                generateRSAKeys();
            }
            break;

        case 'rsa-sign':
            if (moduleKey === 'rsa') {
                showSection('rsa-section');
                scrollToElement('rsa-message-sign');
            }
            break;

        case 'execute-rsa-sign':
            if (currentModule === 'rsa') {
                signRSAMessage();
            }
            break;

        case 'rsa-verify':
            if (moduleKey === 'rsa') {
                showSection('rsa-section');
                scrollToElement('rsa-message-verify');
            }
            break;

        case 'execute-rsa-verify':
            if (currentModule === 'rsa') {
                verifyRSASignature();
            }
            break;

        //MANEJO DE ACCIONES Merkle'
        case 'merkle':
            if (moduleKey === 'hash') {
                showSection('merkle-section');
            }
            break;

        case 'execute-merkle':
            if (currentModule === 'hash') {
                buildMerkleTree();
            }
            break;

        case 'execute-merkle-verify':
            if (currentModule === 'hash') {
                verifyMerkleProof();
            }
            break;

        case 'hash-learn':
            showHashLearnContent();
            break;

        //MANEJO DE ACCIONES POW
        case 'pow-mine':
            if (moduleKey === 'pow') {
                showSection('pow-section');
            }
            break;

        case 'execute-pow-mine':
            if (currentModule === 'pow') {
                startMining();
            }
            break;

        case 'pow-difficulty':
            if (moduleKey === 'pow') {
                showSection('pow-section');
                scrollToElement('pow-target-time');
            }
            break;

        case 'execute-pow-difficulty':
            if (currentModule === 'pow') {
                adjustDifficulty();
            }
            break;

        case 'pow-learn':
            showPowLearnContent();
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
            'aes-encrypt': 'aes-section',
            'rsa-keygen': 'rsa-section',
            'sha256-hash': 'sha256-section',
            'merkle-trees': 'merkle-section',
            'mining-simulation': 'pow-section'
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
        const stepKey = stepName.replace(/\s+/g, '-');

        item.addEventListener('click', () => handleLearningPathClick(stepKey, item));
        item.style.cursor = 'pointer';

        updateProgressItemStyle(item, stepKey);
    });
}
function handleLearningPathClick(stepKey, element) {
    console.log('Learning Path click detectado:', stepKey);

    const stepModuleMap = {
        'one-time-pad-(otp)': 'otp',
        'aes-encryption': 'aes',
        'rsa-cryptography': 'rsa',
        'hash-functions': 'hash',
        'proof-of-work': 'pow'
    };

    const targetModule = stepModuleMap[stepKey];
    console.log('Learning Path:', stepKey, 'hacia', targetModule);

    if (learningProgress.available.includes(stepKey) || learningProgress.completed.includes(stepKey)) {
        if (targetModule) {
            selectModule(targetModule);
            updateCurrentStep(stepKey);
        } else {
            console.warn('Módulo objetivo no encontrado para:', stepKey);
        }
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
        'aes-encryption': 'Completa One-Time Pad para desbloquear AES Encryption.',
        'rsa-cryptography': 'Completa AES Encryption para desbloquear RSA Cryptography.',
        'hash-functions': 'Completa RSA Cryptography para desbloquear Hash Functions.',
        'proof-of-work': 'Completa Hash Functions para desbloquear Proof of Work.'
    };

    alert(messages[stepKey] || 'Este paso aun no esta disponible.');
}
function markStepCompleted(stepKey) {
    console.log('Marcando paso completado:', stepKey);

    if (!learningProgress.completed.includes(stepKey)) {
        learningProgress.completed.push(stepKey);

        // Secuencia correcta de módulos
        const progressSequence = [
            'one-time-pad-(otp)',
            'aes-encryption',
            'rsa-cryptography',
            'hash-functions',
            'proof-of-work'
        ];

        const currentIndex = progressSequence.indexOf(stepKey);

        if (currentIndex >= 0 && currentIndex < progressSequence.length - 1) {
            const nextStep = progressSequence[currentIndex + 1];
            if (!learningProgress.available.includes(nextStep)) {
                learningProgress.available.push(nextStep);
                learningProgress.current = nextStep;
                console.log('Desbloqueando siguiente paso:', nextStep);
            }
        }

        // Actualizar UI
        const progressItems = document.querySelectorAll('.progress-item');
        progressItems.forEach(item => {
            const itemStepKey = item.querySelector('span:last-child').textContent.toLowerCase().replace(/\s+/g, '-');
            updateProgressItemStyle(item, itemStepKey);
        });

        // Mostrar notificación de progreso
        showProgressNotification(stepKey);
    }
}

function updateCurrentStep(stepKey) {
    if (!learningProgress.completed.includes(stepKey)) {
        learningProgress.current = stepKey;

        // Actualizar visualización
        const progressItems = document.querySelectorAll('.progress-item');
        progressItems.forEach(item => {
            const itemStepKey = item.querySelector('span:last-child').textContent.toLowerCase().replace(/\s+/g, '-');
            updateProgressItemStyle(item, itemStepKey);
        });
    }
}

function showProgressNotification(stepKey) {
    const messages = {
        'one-time-pad-(otp)': 'Felicidades! Has completado One-Time Pad. AES Encryption desbloqueado.',
        'aes-encryption': 'Excelente! AES Encryption completado. RSA Cryptography desbloqueado.',
        'rsa-cryptography': 'Muy bien! RSA Cryptography completado. Hash Functions desbloqueado.',
        'hash-functions': 'Perfecto! Hash Functions completado. Proof of Work desbloqueado.',
        'proof-of-work': 'Increíble! Has completado todo el Learning Path!'
    };

    const message = messages[stepKey];
    if (message) {
        // Crear notificación temporal
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 10000;
            font-weight: bold;
            max-width: 300px;
        `;
        notification.textContent = message;

        document.body.appendChild(notification);

        // Remover después de 4 segundos
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 4000);
    }
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

    if (!learningProgress.completed.includes('one-time-pad-(otp)')) {
        markStepCompleted('one-time-pad-(otp)');
    }
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

    // Mostrar pasos si están disponibles
    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('sha256-steps');
        const stepsList = document.getElementById('sha256-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = 'Paso ' + step.step + ': ' + step.operation;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    } else {
        const stepsContainer = document.getElementById('sha256-steps');
        if (stepsContainer) {
            stepsContainer.style.display = 'none';
        }
    }

    resultsArea.scrollIntoView({ behavior: 'smooth' });

    if (!learningProgress.completed.includes('hash-functions')) {
        markStepCompleted('hash-functions');
    }
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

function showOTPLearnContent() {
    // Crear ventana modal o sección con contenido educativo
    const learnContent = `
🎓 ONE-TIME PAD (OTP) - SEGURIDAD PERFECTA

📚 CONCEPTOS CLAVE:
- Clave tan larga como el mensaje.
- Clave completamente aleatoria.
- Clave usada una sola vez.
- Operación XOR bit a bit.

🔒 ¿POR QUÉ ES SEGURO?
- Imposible de romper matemáticamente.
- Cada bit tiene 50% probabilidad de ser 0 o 1.
- Sin patrones detectables.

⚠️ PROBLEMAS PRÁCTICOS:
- Distribución segura de claves.
- Almacenamiento de claves largas.
- Reutilización accidental = vulnerabilidad.

💡 APLICACIONES:
- Comunicaciones militares de alta seguridad.
- Líneas rojas diplomáticas.
- Sistemas críticos de seguridad nacional.
    `;

    alert(learnContent);
}

// AES Encryption functions
async function encryptAES() {
    const message = document.getElementById('aes-message').value;
    const key = document.getElementById('aes-key').value;
    const mode = document.getElementById('aes-mode').value;
    const explain = document.getElementById('aes-explain').checked;

    if (!message.trim()) {
        alert('Please enter a message to encrypt');
        return;
    }

    if (key.length !== 32) {
        alert('Key must be exactly 32 characters for AES-256');
        return;
    }

    try {
        const response = await makeAPIRequest('/aes/encrypt', {
            message: message,
            key: key,
            mode: mode,
            explain: explain
        });

        if (response.success) {
            displayAESResults(response);
        } else {
            alert('AES encryption failed: ' + (response.error || 'Unknown error'));
        }
    } catch (error) {
        alert('AES encryption failed: ' + error.message);
    }
}

// RSA Cryptography functions
async function generateRSAKeys() {
    const keySize = document.getElementById('rsa-key-size').value;
    const explain = document.getElementById('rsa-explain').checked;

    try {
        const response = await makeAPIRequest('/rsa/keygen', {
            keySize: parseInt(keySize),
            explain: explain
        });

        if (response.success) {
            displayRSAKeysResults(response);
        } else {
            alert('Generación de claves RSA falló: ' + (response.error || 'Error desconocido'));
        }
    } catch (error) {
        alert('Generación de claves RSA falló: ' + error.message);
    }
}
// Merkle Tree functions
async function buildMerkleTree() {
    const dataInput = document.getElementById('merkle-data').value;
    const explain = document.getElementById('merkle-explain').checked;

    if (!dataInput.trim()) {
        alert('Por favor ingrese datos para construir el árbol de Merkle.');
        return;
    }

    const dataArray = dataInput.split(',').map(item => item.trim()).filter(item => item.length > 0);

    if (dataArray.length < 2) {
        alert('Se necesitan al menos 2 elementos para construir un árbol de Merkle.');
        return;
    }

    try {
        const response = await makeAPIRequest('/hash/merkle', {
            data: dataArray,
            explain: explain
        });

        if (response.success) {
            displayMerkleResults(response);
        } else {
            alert('Construcción del árbol de Merkle falló: ' + (response.error || 'Error desconocido'));
        }
    } catch (error) {
        alert('Construcción del árbol de Merkle falló: ' + error.message);
    }
}

function displayMerkleResults(response) {
    const resultsArea = document.getElementById('merkle-results');
    resultsArea.style.display = 'block';

    document.getElementById('merkle-original-data').textContent = response.originalData.join(', ');
    document.getElementById('merkle-root').textContent = response.merkleRoot;
    document.getElementById('merkle-leaves-count').textContent = response.leavesCount;
    document.getElementById('merkle-height').textContent = response.treeHeight;

    // Mostrar visualización del árbol
    const treeVisual = document.getElementById('merkle-tree-diagram');
    treeVisual.textContent = response.treeVisualization || 'Visualización no disponible.';

    // Auto-fill verification field
    if (response.originalData.length > 0) {
        document.getElementById('merkle-verify-data').value = response.originalData[0];
        document.getElementById('merkle-proof').value = response.sampleProof || '';
    }

    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('merkle-steps');
        const stepsList = document.getElementById('merkle-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = 'Paso ' + step.step + ': ' + step.operation;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    }

    resultsArea.scrollIntoView({ behavior: 'smooth' });

    if (!learningProgress.completed.includes('hash-functions')) {
        markStepCompleted('hash-functions');
    }
}

async function verifyMerkleProof() {
    const data = document.getElementById('merkle-verify-data').value;
    const proof = document.getElementById('merkle-proof').value;

    if (!data.trim() || !proof.trim()) {
        alert('Por favor ingrese tanto el dato como el proof para verificar.');
        return;
    }

    const proofArray = proof.split(',').map(item => item.trim()).filter(item => item.length > 0);

    try {
        const response = await makeAPIRequest('/hash/merkle-verify', {
            data: data,
            proof: proofArray
        });

        if (response.success) {
            displayMerkleVerifyResults(response);
        } else {
            alert('Verificación de Merkle Proof falló: ' + (response.error || 'Error desconocido'));
        }
    } catch (error) {
        alert('Verificación de Merkle Proof falló: ' + error.message);
    }
}

function displayMerkleVerifyResults(response) {
    const resultsArea = document.getElementById('merkle-verify-results');
    resultsArea.style.display = 'block';

    document.getElementById('merkle-verification-status').textContent = response.valid ? 'VÁLIDO' : 'INVÁLIDO';
    document.getElementById('merkle-verification-status').style.color = response.valid ? '#28a745' : '#dc3545';
    document.getElementById('merkle-verified-data').textContent = response.data;
    document.getElementById('merkle-proof-valid').textContent = response.valid ? 'Sí' : 'No';

    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

function showHashLearnContent() {
    const learnContent = `FUNCIONES HASH CRIPTOGRÁFICAS

SHA-256 (Secure Hash Algorithm 256):
- Función hash criptográfica de 256 bits.
- Parte de la familia SHA-2 desarrollada por NSA.
- Determinística: mismo input = mismo output.
- Avalancha: pequeño cambio = hash completamente diferente.
- Resistente a colisiones y preimágenes.

MERKLE TREE (ÁRBOL DE MERKLE):
- Estructura de datos tipo árbol binario.
- Cada hoja contiene hash de un bloque de datos.
- Cada nodo interno contiene hash de sus hijos.
- Permite verificación eficiente de grandes conjuntos de datos.

APLICACIONES:
- Bitcoin y otras criptomonedas.
- Sistemas de archivos distribuidos.
- Verificación de integridad en bases de datos.
- Protocolos de consenso blockchain.

VENTAJAS DE MERKLE TREES:
- Verificación O(log n) en lugar de O(n).
- Detección eficiente de cambios.
- Sincronización rápida entre nodos.
- Pruebas criptográficas compactas.`;

    alert(learnContent);
}

function displayRSAKeysResults(response) {
    const resultsArea = document.getElementById('rsa-keys-results');
    resultsArea.style.display = 'block';

    document.getElementById('rsa-key-size-result').textContent = response.keySize + ' bits';
    document.getElementById('rsa-public-key').textContent = response.publicKey;
    document.getElementById('rsa-private-key').textContent = response.privateKey;
    document.getElementById('rsa-modulus').textContent = response.modulus;

    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('rsa-keygen-steps');
        const stepsList = document.getElementById('rsa-keygen-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = 'Paso ' + step.step + ': ' + step.operation;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    }

    resultsArea.scrollIntoView({ behavior: 'smooth' });

    if (!learningProgress.completed.includes('rsa-cryptography')) {
        markStepCompleted('rsa-cryptography');
    }
}

async function signRSAMessage() {
    const message = document.getElementById('rsa-message-sign').value;
    const explain = document.getElementById('rsa-sign-explain').checked;

    if (!message.trim()) {
        alert('Por favor ingrese un mensaje para firmar.');
        return;
    }

    try {
        const response = await makeAPIRequest('/rsa/sign', {
            message: message,
            explain: explain
        });

        if (response.success) {
            displayRSASignResults(response);
            // Auto-fill verification fields
            document.getElementById('rsa-message-verify').value = message;
            document.getElementById('rsa-signature-verify').value = response.signature;
        } else {
            alert('Firma RSA falló: ' + (response.error || 'Error desconocido'));
        }
    } catch (error) {
        alert('Firma RSA falló: ' + error.message);
    }
}

function displayRSASignResults(response) {
    const resultsArea = document.getElementById('rsa-sign-results');
    resultsArea.style.display = 'block';

    document.getElementById('rsa-signed-message').textContent = response.message;
    document.getElementById('rsa-message-hash').textContent = response.messageHash;
    document.getElementById('rsa-signature').textContent = response.signature;

    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('rsa-sign-steps');
        const stepsList = document.getElementById('rsa-sign-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = 'Paso ' + step.step + ': ' + step.operation;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    }

    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

async function verifyRSASignature() {
    const message = document.getElementById('rsa-message-verify').value;
    const signature = document.getElementById('rsa-signature-verify').value;
    const explain = document.getElementById('rsa-verify-explain').checked;

    if (!message.trim() || !signature.trim()) {
        alert('Por favor ingrese tanto el mensaje como la firma para verificar.');
        return;
    }

    try {
        const response = await makeAPIRequest('/rsa/verify', {
            message: message,
            signature: signature,
            explain: explain
        });

        if (response.success) {
            displayRSAVerifyResults(response);
        } else {
            alert('Verificación RSA falló: ' + (response.error || 'Error desconocido'));
        }
    } catch (error) {
        alert('Verificación RSA falló: ' + error.message);
    }
}

function displayRSAVerifyResults(response) {
    const resultsArea = document.getElementById('rsa-verify-results');
    resultsArea.style.display = 'block';

    document.getElementById('rsa-verification-status').textContent = response.valid ? 'VÁLIDA' : 'INVÁLIDA';
    document.getElementById('rsa-verification-status').style.color = response.valid ? '#28a745' : '#dc3545';
    document.getElementById('rsa-verified-message').textContent = response.message;
    document.getElementById('rsa-integrity-status').textContent = response.valid ? 'Integridad confirmada' : 'Integridad comprometida';

    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('rsa-verify-steps');
        const stepsList = document.getElementById('rsa-verify-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = 'Paso ' + step.step + ': ' + step.operation;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    }

    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

function scrollToElement(elementId) {
    setTimeout(() => {
        const element = document.getElementById(elementId);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }, 300);
}

function displayAESResults(response) {
    const resultsArea = document.getElementById('aes-results');
    resultsArea.style.display = 'block';

    document.getElementById('aes-original').textContent = response.message;
    document.getElementById('aes-used-key').textContent = response.key;
    document.getElementById('aes-used-mode').textContent = response.mode;
    document.getElementById('aes-ciphertext').textContent = response.ciphertext;
    document.getElementById('aes-iv').textContent = response.iv || 'N/A';

    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('aes-steps');
        const stepsList = document.getElementById('aes-steps-list');

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

    if (!learningProgress.completed.includes('aes-encryption')) {
        markStepCompleted('aes-encryption');
    }
}

function showAESLearnContent() {
    const learnContent = `ESTÁNDAR DE CIFRADO AVANZADO (AES)

CARACTERÍSTICAS PRINCIPALES:
- Cifrado por bloques de 128 bits.
- Tamaños de clave: 128, 192 o 256 bits.
- Estándar de la industria desde 2001.
- Usado globalmente en comunicaciones seguras.

MODOS DE CIFRADO:
- CBC: Cifrado en cadena de bloques - seguro con IV.
- ECB: Libro de códigos electrónico - simple pero inseguro.
- CTR: Modo contador - comportamiento de cifrado de flujo.

SEGURIDAD:
- Resistente a ataques cuánticos para fines prácticos.
- No se conocen ataques prácticos exitosos.
- Utilizado por gobiernos y corporaciones a nivel mundial.

APLICACIONES:
- Seguridad web HTTPS/TLS.
- Cifrado de archivos y discos.
- Conexiones VPN.
- Aplicaciones de mensajería segura.`;

    alert(learnContent);
}

// Proof of Work functions
let miningInterval = null;
let miningStartTime = null;
let miningAttempts = 0;

async function startMining() {
    const blockData = document.getElementById('pow-block-data').value;
    const previousHash = document.getElementById('pow-previous-hash').value;
    const difficulty = parseInt(document.getElementById('pow-difficulty').value);
    const explain = document.getElementById('pow-explain').checked;

    if (!blockData.trim() || !previousHash.trim()) {
        alert('Por favor complete todos los campos requeridos.');
        return;
    }

    // Mostrar estado de minado
    const statusArea = document.getElementById('pow-mining-status');
    statusArea.style.display = 'block';

    // Ocultar resultados anteriores
    document.getElementById('pow-results').style.display = 'none';

    // Configurar botones
    document.querySelector('[data-action="execute-pow-mine"]').style.display = 'none';
    document.getElementById('pow-stop-btn').style.display = 'inline-block';

    try {
        const response = await makeAPIRequest('/pow/mine', {
            blockData: blockData,
            previousHash: previousHash,
            difficulty: difficulty,
            explain: explain
        });

        if (response.success) {
            simulateMining(response);
        } else {
            alert('Inicio de minado falló: ' + (response.error || 'Error desconocido'));
            resetMiningUI();
        }
    } catch (error) {
        alert('Inicio de minado falló: ' + error.message);
        resetMiningUI();
    }
}

function simulateMining(response) {
    miningStartTime = Date.now();
    miningAttempts = 0;

    document.getElementById('pow-status').textContent = 'Minando...';

    const targetAttempts = response.expectedAttempts || 1000;
    const updateInterval = Math.max(1, Math.floor(targetAttempts / 100));

    miningInterval = setInterval(() => {
        miningAttempts += Math.floor(Math.random() * 10) + 1;

        const elapsed = (Date.now() - miningStartTime) / 1000;
        const hashRate = Math.floor(miningAttempts / elapsed);

        document.getElementById('pow-attempts').textContent = miningAttempts.toLocaleString();
        document.getElementById('pow-hashrate').textContent = hashRate.toLocaleString() + ' H/s';
        document.getElementById('pow-time').textContent = elapsed.toFixed(1) + ' s';

        // Simular encontrar el nonce
        if (miningAttempts >= targetAttempts || elapsed > 30) {
            clearInterval(miningInterval);
            miningInterval = null;

            document.getElementById('pow-status').textContent = 'Bloque encontrado!';

            setTimeout(() => {
                displayPowResults(response, miningAttempts, elapsed);
                resetMiningUI();
            }, 1000);
        }
    }, 100);
}

function stopMining() {
    if (miningInterval) {
        clearInterval(miningInterval);
        miningInterval = null;
    }

    document.getElementById('pow-status').textContent = 'Minado detenido por el usuario.';
    resetMiningUI();
}

function resetMiningUI() {
    document.querySelector('[data-action="execute-pow-mine"]').style.display = 'inline-block';
    document.getElementById('pow-stop-btn').style.display = 'none';
}

function displayPowResults(response, attempts, timeElapsed) {
    const resultsArea = document.getElementById('pow-results');
    resultsArea.style.display = 'block';

    document.getElementById('pow-mined-data').textContent = response.blockData;
    document.getElementById('pow-mined-prev-hash').textContent = response.previousHash;
    document.getElementById('pow-nonce').textContent = response.nonce;
    document.getElementById('pow-block-hash').textContent = response.blockHash;
    document.getElementById('pow-final-difficulty').textContent = response.difficulty + ' ceros iniciales';
    document.getElementById('pow-total-attempts').textContent = attempts.toLocaleString();
    document.getElementById('pow-total-time').textContent = timeElapsed.toFixed(2) + ' segundos';

    if (response.steps && response.steps.length > 0) {
        const stepsContainer = document.getElementById('pow-steps');
        const stepsList = document.getElementById('pow-steps-list');

        stepsList.innerHTML = '';
        response.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'step-item';
            stepDiv.textContent = 'Paso ' + step.step + ': ' + step.operation;
            stepsList.appendChild(stepDiv);
        });

        stepsContainer.style.display = 'block';
    }

    resultsArea.scrollIntoView({ behavior: 'smooth' });

    if (!learningProgress.completed.includes('proof-of-work')) {
        markStepCompleted('proof-of-work');
    }
}

async function adjustDifficulty() {
    const targetTime = parseInt(document.getElementById('pow-target-time').value);
    const actualTime = parseInt(document.getElementById('pow-actual-time').value);

    if (targetTime <= 0 || actualTime <= 0) {
        alert('Por favor ingrese tiempos válidos mayores a cero.');
        return;
    }

    try {
        const response = await makeAPIRequest('/pow/difficulty', {
            targetTime: targetTime,
            actualTime: actualTime,
            currentDifficulty: parseInt(document.getElementById('pow-difficulty').value)
        });

        if (response.success) {
            displayDifficultyResults(response);
        } else {
            alert('Cálculo de dificultad falló: ' + (response.error || 'Error desconocido'));
        }
    } catch (error) {
        alert('Cálculo de dificultad falló: ' + error.message);
    }
}

function displayDifficultyResults(response) {
    const resultsArea = document.getElementById('pow-difficulty-results');
    resultsArea.style.display = 'block';

    document.getElementById('pow-current-difficulty').textContent = response.currentDifficulty + ' ceros';
    document.getElementById('pow-new-difficulty').textContent = response.newDifficulty + ' ceros';
    document.getElementById('pow-adjustment-factor').textContent = 'x' + response.adjustmentFactor.toFixed(4);

    const change = response.newDifficulty - response.currentDifficulty;
    const changeText = change > 0 ? '+' + change + ' (Incremento)' : change + ' (Decremento)';
    const changeColor = change > 0 ? '#dc3545' : '#28a745';

    document.getElementById('pow-difficulty-change').textContent = changeText;
    document.getElementById('pow-difficulty-change').style.color = changeColor;

    // Actualizar selector de dificultad
    document.getElementById('pow-difficulty').value = response.newDifficulty;

    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

function showPowLearnContent() {
    const learnContent = `PROOF OF WORK (PRUEBA DE TRABAJO)

CONCEPTO FUNDAMENTAL:
- Algoritmo de consenso utilizado en Bitcoin.
- Requiere esfuerzo computacional para validar bloques.
- Los mineros compiten para resolver un puzzle criptográfico.
- El primero en resolver el puzzle gana la recompensa.

PROCESO DE MINADO:
- Recopilar transacciones pendientes.
- Calcular hash del bloque anterior.
- Encontrar un nonce que produzca un hash con ceros iniciales.
- Más ceros requeridos = mayor dificultad.

AJUSTE DE DIFICULTAD:
- Bitcoin ajusta dificultad cada 2016 bloques.
- Objetivo: mantener 10 minutos por bloque.
- Si los bloques son muy rápidos → aumenta dificultad.
- Si los bloques son muy lentos → disminuye dificultad.

SEGURIDAD:
- Alterar histórico requiere rehacer todo el trabajo.
- Costo computacional hace ataques impracticables.
- Red descentralizada valida cada bloque.

DESVENTAJAS:
- Alto consumo energético.
- Escalabilidad limitada.
- Centralización en pools de minado.`;

    alert(learnContent);
}

console.log('TEST FINAL - app.js completado');
