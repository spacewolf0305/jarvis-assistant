/* ═══════════════════════════════════════════════════════
   J.A.R.V.I.S — Waveform Visualizer
   Real-time audio visualization on the orb
   ═══════════════════════════════════════════════════════ */

let waveformCanvas, waveformCtx;
let waveformActive = false;
let currentVisualizerState = 'idle';

function initVisualizer() {
    waveformCanvas = document.getElementById('waveform-canvas');
    if (!waveformCanvas) return;
    waveformCtx = waveformCanvas.getContext('2d');
    resizeWaveformCanvas();
    window.addEventListener('resize', resizeWaveformCanvas);
    animateWaveform();
}

function resizeWaveformCanvas() {
    if (waveformCanvas) {
        const container = waveformCanvas.parentElement;
        waveformCanvas.width = container.offsetWidth;
        waveformCanvas.height = container.offsetHeight;
    }
}

function setVisualizerState(state) {
    currentVisualizerState = state;
}

function animateWaveform() {
    if (!waveformCtx) {
        requestAnimationFrame(animateWaveform);
        return;
    }

    const w = waveformCanvas.width;
    const h = waveformCanvas.height;
    const cx = w / 2;
    const cy = h / 2;

    waveformCtx.clearRect(0, 0, w, h);

    const time = Date.now() / 1000;

    switch (currentVisualizerState) {
        case 'listening':
            drawListeningWave(cx, cy, time);
            break;
        case 'processing':
            drawProcessingEffect(cx, cy, time);
            break;
        case 'speaking':
            drawSpeakingWave(cx, cy, time);
            break;
        default:
            drawIdleWave(cx, cy, time);
    }

    requestAnimationFrame(animateWaveform);
}

function drawIdleWave(cx, cy, time) {
    // Subtle breathing circle
    const radius = 52 + Math.sin(time * 0.8) * 3;
    waveformCtx.beginPath();
    waveformCtx.arc(cx, cy, radius, 0, Math.PI * 2);
    waveformCtx.strokeStyle = 'rgba(0, 212, 255, 0.1)';
    waveformCtx.lineWidth = 1;
    waveformCtx.stroke();
}

function drawListeningWave(cx, cy, time) {
    // Active circular waveform
    const baseRadius = 55;
    const points = 64;

    for (let ring = 0; ring < 3; ring++) {
        waveformCtx.beginPath();
        const ringOffset = ring * 8;
        const alpha = 0.3 - ring * 0.1;

        for (let i = 0; i <= points; i++) {
            const angle = (i / points) * Math.PI * 2;
            const noise = Math.sin(angle * 4 + time * 3) * 6 +
                          Math.sin(angle * 7 + time * 5) * 3 +
                          Math.sin(angle * 2 + time * 2) * 4;
            const r = baseRadius + ringOffset + noise;
            const x = cx + Math.cos(angle) * r;
            const y = cy + Math.sin(angle) * r;

            if (i === 0) {
                waveformCtx.moveTo(x, y);
            } else {
                waveformCtx.lineTo(x, y);
            }
        }

        waveformCtx.closePath();
        waveformCtx.strokeStyle = `rgba(0, 255, 136, ${alpha})`;
        waveformCtx.lineWidth = 1.5 - ring * 0.3;
        waveformCtx.stroke();
    }
}

function drawProcessingEffect(cx, cy, time) {
    // Spinning arcs
    const segments = 8;
    for (let i = 0; i < segments; i++) {
        const startAngle = (i / segments) * Math.PI * 2 + time * 3;
        const endAngle = startAngle + Math.PI / segments;
        const radius = 55 + Math.sin(time * 2 + i) * 5;

        waveformCtx.beginPath();
        waveformCtx.arc(cx, cy, radius, startAngle, endAngle);
        waveformCtx.strokeStyle = `rgba(255, 170, 0, ${0.3 + Math.sin(time * 4 + i) * 0.2})`;
        waveformCtx.lineWidth = 2;
        waveformCtx.stroke();
    }

    // Inner spinning dots
    for (let i = 0; i < 12; i++) {
        const angle = (i / 12) * Math.PI * 2 + time * 2;
        const r = 42;
        const x = cx + Math.cos(angle) * r;
        const y = cy + Math.sin(angle) * r;

        waveformCtx.beginPath();
        waveformCtx.arc(x, y, 1.5, 0, Math.PI * 2);
        waveformCtx.fillStyle = `rgba(255, 170, 0, ${0.5 + Math.sin(time * 3 + i) * 0.3})`;
        waveformCtx.fill();
    }
}

function drawSpeakingWave(cx, cy, time) {
    // Pulsating bars radiating from center
    const bars = 32;
    for (let i = 0; i < bars; i++) {
        const angle = (i / bars) * Math.PI * 2;
        const barHeight = 8 + Math.sin(angle * 3 + time * 6) * 12 +
                         Math.sin(angle * 5 + time * 4) * 6;
        const innerR = 50;
        const outerR = innerR + Math.max(2, barHeight);

        const x1 = cx + Math.cos(angle) * innerR;
        const y1 = cy + Math.sin(angle) * innerR;
        const x2 = cx + Math.cos(angle) * outerR;
        const y2 = cy + Math.sin(angle) * outerR;

        waveformCtx.beginPath();
        waveformCtx.moveTo(x1, y1);
        waveformCtx.lineTo(x2, y2);
        waveformCtx.strokeStyle = `rgba(0, 212, 255, ${0.4 + barHeight / 40})`;
        waveformCtx.lineWidth = 2;
        waveformCtx.lineCap = 'round';
        waveformCtx.stroke();
    }
}
