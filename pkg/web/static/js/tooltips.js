
// TOOLTIPS EDUCATIVOS CON TIPPY.JS - CryptoToolkit-Go


class CryptoTooltips {
    constructor() {
        this.tooltipData = this.getTooltipDefinitions();
        this.loadTippyJS();
    }

    getTooltipDefinitions() {
        return {
            'otp': {
                title: 'One-Time Pad',
                content: 'Método de cifrado con seguridad perfecta. Usa una clave aleatoria del mismo tamaño que el mensaje.',
                example: '💡 Si tu mensaje es "HOLA", necesitas una clave de 4 caracteres aleatorios.'
            },
            'aes': {
                title: 'AES Encryption',
                content: 'Algoritmo de cifrado simétrico usado mundialmente. Es el estándar del gobierno de EE.UU.',
                example: '💡 Tu tarjeta de crédito usa AES para proteger tus datos cuando compras online.'
            },
            'rsa': {
                title: 'RSA Cryptography',
                content: 'Rivest-Shamir-Adleman (RSA). Criptografía de clave pública. Tienes dos claves: una pública y una privada.',
                example: '💡 Como un buzón público donde todos pueden depositar cartas, pero solo tú tienes la llave.'
            },
            'rsa-keygen': {
                title: 'KeyGen',
                content: 'Generación de claves - Crear par de claves pública y privada RSA.',
                example: ''
            },
            'rsa-sign': {
                title: 'Sign',
                content: 'Firma digital - Crear firma criptográfica para autenticar mensajes.',
                example: ''
            },
            'rsa-verify': {
                title: 'Verify',
                content: 'Verificación - Comprobar la autenticidad e integridad de firmas digitales.',
                example: ''
            },
            'sha256': {
                title: 'SHA-256 Hash',
                content: 'Convierte cualquier texto en un código único de 64 caracteres. Cambiar una letra cambia todo el hash.',
                example: '💡 "Hola" siempre produce el mismo hash, pero "hola" produce uno completamente diferente.'
            },
            'merkle': {
                title: 'Árbol de Merkle',
                content: 'Estructura que permite verificar datos específicos sin descargar todo el conjunto.',
                example: '💡 Como un índice de biblioteca que te dice si un libro existe sin revisar todos los estantes.'
            },
            'pow': {
                title: 'Proof of Work',
                content: 'Prueba de Trabajo (PoW). Sistema donde computadoras compiten resolviendo problemas matemáticos para validar transacciones.',
                example: '💡 Como un concurso donde el primero en resolver un rompecabezas gana el derecho a escribir en el libro.'
            },

            'pow-mine': {
                title: 'Mine',
                content: 'Minar - Proceso de encontrar un nonce válido que produzca un hash con la dificultad requerida.',
                example: ''
            },

            'pow-difficulty': {
                title: 'Difficulty++',
                content: 'Ajustar Dificultad - Calcular nueva dificultad basada en tiempo objetivo vs tiempo actual.',
                example: ''
            },
            'encrypt': {
                title: 'Cifrar',
                content: 'Advanced Encryption Standard (AES) - Estándar de cifrado simétrico más utilizado mundialmente. Convertir texto normal en código secreto que solo puede ser leído con la clave correcta.',
                example: '💡 "mensaje secreto" → "x9k2$mz8@p1w5n"'
            },

            'break': {
                title: 'Vulnerabilidad',
                content: 'Demostración de cómo los errores en criptografía pueden comprometer la seguridad.',
                example: '💡 Reutilizar claves OTP es como usar la misma contraseña en múltiples sitios.'
            },
            'step-by-step': {
                title: 'Explicación Detallada',
                content: 'Muestra cada operación matemática del algoritmo para entender cómo funciona internamente.',
                example: '💡 Ver cada suma, XOR y transformación que hace el algoritmo en tiempo real.'
            },
            'key': {
                title: 'Clave Criptográfica',
                content: 'Información secreta usada para cifrar y descifrar mensajes.',
                example: '💡 Como la contraseña que protege tus datos, pero mucho más compleja.'
            },
            'hash': {
                title: 'Hash',
                content: 'Función que convierte cualquier dato en un código de tamaño fijo.',
                example: '💡 Como una huella digital única para cada archivo o mensaje.'
            }
        };
    }

    loadTippyJS() {
        console.log('🔧 Cargando Tippy.js...');

        // Cargar Popper.js primero
        const popperScript = document.createElement('script');
        popperScript.src = 'https://unpkg.com/@popperjs/core@2';
        popperScript.onload = () => {
            console.log('✅ Popper.js cargado');

            // Luego cargar Tippy.js
            const tippyScript = document.createElement('script');
            tippyScript.src = 'https://unpkg.com/tippy.js@6';
            tippyScript.onload = () => {
                console.log('✅ Tippy.js cargado');
                this.setupTooltips(); // ✅ CORRECTO - nombre diferente
            };
            tippyScript.onerror = () => {
                console.error('❌ Error cargando Tippy.js');
            };
            document.head.appendChild(tippyScript);
        };
        popperScript.onerror = () => {
            console.error('❌ Error cargando Popper.js');
        };
        document.head.appendChild(popperScript);

        // Cargar CSS de Tippy.js
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = 'https://unpkg.com/tippy.js@6/themes/dark.css';
        document.head.appendChild(link);
    }

    setupTooltips() {
        // Verificar que tippy esté disponible
        if (typeof tippy === 'undefined') {
            console.log('⏳ Esperando a que tippy esté disponible...');
            setTimeout(() => this.setupTooltips(), 100);
            return;
        }

        console.log('🎯 Configurando tooltips...');

        // Dar tiempo para que el DOM esté completamente renderizado
        setTimeout(() => {
            this.addTooltipToModules();
            this.addTooltipToButtons();
            this.addTooltipToElements();
            console.log('✅ Tooltips configurados');
        }, 1000);
    }

    addTooltipToModules() {
        console.log('📁 Agregando tooltips a módulos...');

        // Módulos principales por clase
        this.addTooltip('.otp-module h4', 'otp');
        this.addTooltip('.hash-module h4', 'sha256');

        // Buscar por texto en módulos
        this.addTooltipByText('AES Encryption', 'aes');
        this.addTooltipByText('RSA Cryptography', 'rsa');
        this.addTooltipByText('Proof of Work', 'pow');
        this.addTooltipByText('Merkle', 'merkle');
    }

    addTooltipToButtons() {
        console.log('🔘 Agregando tooltips a botones...');

        // Botones específicos
        this.addTooltipByText('Encrypt', 'encrypt');
        this.addTooltipByText('Break', 'break');
        this.addTooltipByText('SHA-256', 'sha256');
        this.addTooltipByText('KeyGen', 'rsa-keygen');
        this.addTooltipByText('Sign', 'rsa-sign');
        this.addTooltipByText('Verify', 'rsa-verify');
        this.addTooltipByText('Mine', 'pow-mine');
        this.addTooltipByText('Difficulty++', 'pow-difficulty');


        // Checkboxes y labels
        this.addTooltipByText('Show step-by-step explanation', 'step-by-step');
        this.addTooltipByText('Show algorithm steps', 'step-by-step');
    }

    addTooltipToElements() {
        console.log('📊 Agregando tooltips a elementos...');

        // Elementos de resultado
        this.addTooltipByText('Generated Key:', 'key');
        this.addTooltipByText('Ciphertext:', 'encrypt');
        this.addTooltipByText('Hash', 'hash');
    }

    addTooltip(selector, key) {
        const elements = document.querySelectorAll(selector);
        console.log(`🔍 Selector "${selector}" encontró ${elements.length} elementos`);
        elements.forEach(element => {
            this.createTooltip(element, key);
        });
    }

    addTooltipByText(text, key) {
        let found = 0;
        const elements = document.querySelectorAll('*');

        elements.forEach(element => {
            if (element.children.length === 0 && element.textContent.trim().includes(text)) {
                this.createTooltip(element, key);
                found++;
            }
        });

        console.log(`🔍 Texto "${text}" encontrado en ${found} elementos`);
    }

    createTooltip(element, key) {
        const tooltipData = this.tooltipData[key];
        if (!tooltipData) {
            console.warn(`⚠️ No hay datos de tooltip para: ${key}`);
            return;
        }

        const content = `
            <div style="text-align: left; max-width: 300px;">
                <div style="font-weight: bold; color: #3282b8; margin-bottom: 8px; font-size: 14px;">
                    ${tooltipData.title}
                </div>
                <div style="margin-bottom: 8px; line-height: 1.4; font-size: 13px;">
                    ${tooltipData.content}
                </div>
                <div style="font-size: 12px; color: #bbe1fa; font-style: italic;">
                    ${tooltipData.example}
                </div>
            </div>
        `;

        try {
            tippy(element, {
                content: content,
                allowHTML: true,
                theme: 'dark',
                placement: 'top',
                arrow: true,
                delay: [300, 100],
                duration: [300, 200],
                interactive: true,
                maxWidth: 350,
                hideOnClick: false,
                trigger: 'mouseenter focus'
            });

            // Agregar estilo sutil al elemento
            element.style.borderBottom = '1px dotted #3282b8';
            element.style.cursor = 'help';

            console.log(`✅ Tooltip agregado a: ${element.textContent.trim().substring(0, 20)}...`);

        } catch (error) {
            console.error('❌ Error creando tooltip:', error);
        }
    }
}

// Inicializar cuando la página esté lista
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 DOM cargado, inicializando CryptoTooltips...');
    new CryptoTooltips();
});

// También inicializar si la página ya está cargada
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    console.log('🚀 Página ya cargada, inicializando CryptoTooltips...');
    new CryptoTooltips();
}