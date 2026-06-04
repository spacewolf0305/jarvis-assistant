/* ═══════════════════════════════════════════════════════
   J.A.R.V.I.S — Animations Engine
   Boot sequence, particles, scan lines
   ═══════════════════════════════════════════════════════ */

// ─── Boot Sequence ──────────────────────────────────────
function runBootSequence() {
    const progressBar = document.getElementById('boot-progress-bar');
    const statusText = document.getElementById('boot-status');
    const bootScreen = document.getElementById('boot-screen');
    const hudContainer = document.getElementById('hud-container');

    const steps = [
        { progress: 15, text: 'Loading core systems...' },
        { progress: 30, text: 'Initializing voice engine...' },
        { progress: 45, text: 'Connecting to security modules...' },
        { progress: 60, text: 'Calibrating neural interface...' },
        { progress: 75, text: 'Establishing WebSocket link...' },
        { progress: 88, text: 'Loading HUD interface...' },
        { progress: 100, text: 'All systems online.' },
    ];

    let i = 0;
    const interval = setInterval(() => {
        if (i < steps.length) {
            progressBar.style.width = steps[i].progress + '%';
            statusText.textContent = steps[i].text;
            i++;
        } else {
            clearInterval(interval);
            setTimeout(() => {
                bootScreen.style.opacity = '0';
                bootScreen.style.transition = 'opacity 0.5s ease';
                setTimeout(() => {
                    bootScreen.classList.add('hidden');
                    hudContainer.classList.remove('hidden');
                    hudContainer.style.opacity = '0';
                    hudContainer.style.transition = 'opacity 0.8s ease';
                    requestAnimationFrame(() => {
                        hudContainer.style.opacity = '1';
                    });
                    initParticles();
                    startClock();
                }, 500);
            }, 600);
        }
    }, 400);
}

// ─── Particle System ────────────────────────────────────
let particles = [];
let particleCanvas, particleCtx;

function initParticles() {
    particleCanvas = document.getElementById('particle-canvas');
    particleCtx = particleCanvas.getContext('2d');

    resizeParticleCanvas();
    window.addEventListener('resize', resizeParticleCanvas);

    // Create particles
    const count = Math.min(60, Math.floor(window.innerWidth / 25));
    particles = [];
    for (let i = 0; i < count; i++) {
        particles.push({
            x: Math.random() * particleCanvas.width,
            y: Math.random() * particleCanvas.height,
            vx: (Math.random() - 0.5) * 0.3,
            vy: (Math.random() - 0.5) * 0.3,
            radius: Math.random() * 1.5 + 0.5,
            alpha: Math.random() * 0.3 + 0.1,
        });
    }

    animateParticles();
}

function resizeParticleCanvas() {
    if (particleCanvas) {
        particleCanvas.width = window.innerWidth;
        particleCanvas.height = window.innerHeight;
    }
}

function animateParticles() {
    if (!particleCtx) return;

    particleCtx.clearRect(0, 0, particleCanvas.width, particleCanvas.height);

    // Update and draw particles
    particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;

        // Wrap around screen
        if (p.x < 0) p.x = particleCanvas.width;
        if (p.x > particleCanvas.width) p.x = 0;
        if (p.y < 0) p.y = particleCanvas.height;
        if (p.y > particleCanvas.height) p.y = 0;

        particleCtx.beginPath();
        particleCtx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        particleCtx.fillStyle = `rgba(0, 212, 255, ${p.alpha})`;
        particleCtx.fill();
    });

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 120) {
                const alpha = (1 - dist / 120) * 0.08;
                particleCtx.beginPath();
                particleCtx.moveTo(particles[i].x, particles[i].y);
                particleCtx.lineTo(particles[j].x, particles[j].y);
                particleCtx.strokeStyle = `rgba(0, 212, 255, ${alpha})`;
                particleCtx.lineWidth = 0.5;
                particleCtx.stroke();
            }
        }
    }

    requestAnimationFrame(animateParticles);
}

// ─── Clock ──────────────────────────────────────────────
function startClock() {
    const clockEl = document.getElementById('clock');
    function update() {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }
    update();
    setInterval(update, 1000);
}

// ─── Typing Effect ──────────────────────────────────────
function typeText(element, text, speed = 20) {
    return new Promise(resolve => {
        element.innerHTML = '';
        let i = 0;
        const cursor = document.createElement('span');
        cursor.className = 'typing-cursor';

        function type() {
            if (i < text.length) {
                element.textContent = text.substring(0, i + 1);
                element.appendChild(cursor);
                i++;
                setTimeout(type, speed);
            } else {
                setTimeout(() => {
                    cursor.remove();
                    resolve();
                }, 500);
            }
        }
        type();
    });
}
