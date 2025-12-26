/**
 * Real-Time IDS Dashboard - JavaScript Logic
 * Updated to use 30 model features for accurate predictions
 */

// ============================================================
// Configuration
// ============================================================
const CONFIG = {
    pollInterval: 2000,
    eventsLimit: 50,
    apiBase: ''
};

// Store 30 model features (loaded from API)
let MODEL_FEATURES = [];

// Store current preset features (complete 30-feature set)
let currentPresetFeatures = {};

// ============================================================
// DOM Elements
// ============================================================
const elements = {
    totalFlows: document.getElementById('total-flows'),
    benignFlows: document.getElementById('benign-flows'),
    attackFlows: document.getElementById('attack-flows'),
    accuracy: document.getElementById('accuracy'),
    attackChart: document.getElementById('attack-chart'),
    eventsTableBody: document.getElementById('events-table-body'),
    manualTestForm: document.getElementById('manual-test-form'),
    predictionResult: document.getElementById('prediction-result'),
    presetButtons: document.getElementById('preset-buttons'),
    resetBtn: document.getElementById('reset-btn'),
    featuresFormGrid: document.getElementById('features-form-grid'),
    selectedPreset: document.getElementById('selected-preset'),
    recallPortscan: document.getElementById('recall-portscan'),
    recallPortscanValue: document.getElementById('recall-portscan-value'),
    recallDdos: document.getElementById('recall-ddos'),
    recallDdosValue: document.getElementById('recall-ddos-value'),
    recallHulk: document.getElementById('recall-hulk'),
    recallHulkValue: document.getElementById('recall-hulk-value'),
    recallBenign: document.getElementById('recall-benign'),
    recallBenignValue: document.getElementById('recall-benign-value'),
};

// ============================================================
// API Functions
// ============================================================

async function fetchStats() {
    try {
        const response = await fetch(`${CONFIG.apiBase}/api/stats`);
        const stats = await response.json();
        updateMetrics(stats);
        updateRecallBars(stats);
        updateAttackChart(stats.by_type);
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

async function fetchEvents() {
    try {
        const response = await fetch(`${CONFIG.apiBase}/api/events?limit=${CONFIG.eventsLimit}`);
        const events = await response.json();
        updateEventsTable(events);
    } catch (error) {
        console.error('Error fetching events:', error);
    }
}

/**
 * Load model features from API and generate form inputs
 */
async function loadModelFeatures() {
    try {
        const response = await fetch(`${CONFIG.apiBase}/api/model_features`);
        const data = await response.json();

        MODEL_FEATURES = data.features;
        currentPresetFeatures = { ...data.defaults };

        // Generate form inputs for all 30 features
        generateFeatureInputs(MODEL_FEATURES, data.defaults);

        console.log(`Loaded ${MODEL_FEATURES.length} model features`);
    } catch (error) {
        console.error('Error loading model features:', error);
        elements.featuresFormGrid.innerHTML = '<div class="loading-features">Error loading features</div>';
    }
}

/**
 * Generate form input fields for all model features
 */
function generateFeatureInputs(features, defaults) {
    const grid = elements.featuresFormGrid;
    grid.innerHTML = '';

    features.forEach((featureName, index) => {
        const formGroup = document.createElement('div');
        formGroup.className = 'form-group';

        const label = document.createElement('label');
        label.htmlFor = `feature_${index}`;
        label.textContent = featureName;
        label.title = featureName;

        const input = document.createElement('input');
        input.type = 'number';
        input.id = `feature_${index}`;
        input.name = featureName;
        input.value = defaults[featureName] || 0;
        input.step = 'any';

        formGroup.appendChild(label);
        formGroup.appendChild(input);
        grid.appendChild(formGroup);
    });
}

/**
 * Load preset and fill all 30 feature inputs
 */
async function loadPreset(presetName) {
    try {
        const response = await fetch(`${CONFIG.apiBase}/api/preset/${presetName}`);
        const preset = await response.json();

        if (preset.features) {
            // Store all 30 preset features
            currentPresetFeatures = { ...preset.features };

            // Update selected preset display
            if (elements.selectedPreset) {
                const attackType = preset.attack_type || preset.name || presetName;
                elements.selectedPreset.textContent = `Selected: ${attackType}`;
            }

            // Fill all form inputs
            MODEL_FEATURES.forEach((featureName, index) => {
                const input = document.getElementById(`feature_${index}`);
                if (input && featureName in preset.features) {
                    const val = preset.features[featureName];
                    input.value = Number.isInteger(val) ? val : parseFloat(val).toFixed(2);
                }
            });

            console.log(`Loaded preset "${presetName}" with ${Object.keys(preset.features).length} features`);
        }
    } catch (error) {
        console.error('Error loading preset:', error);
    }
}

/**
 * Submit prediction using /api/predict_direct (30 features directly to model)
 */
async function submitPrediction(features) {
    try {
        const response = await fetch(`${CONFIG.apiBase}/api/predict_direct`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ features })
        });
        const result = await response.json();
        displayPredictionResult(result);
        fetchEvents();
        fetchStats();
    } catch (error) {
        console.error('Error submitting prediction:', error);
    }
}

async function resetStats() {
    try {
        await fetch(`${CONFIG.apiBase}/api/reset`, { method: 'POST' });
        fetchStats();
        fetchEvents();
    } catch (error) {
        console.error('Error resetting stats:', error);
    }
}

// ============================================================
// UI Update Functions
// ============================================================

function animateValue(element, start, end) {
    if (start === end) return;
    const duration = 300;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const current = Math.floor(start + (end - start) * progress);
        element.textContent = current.toLocaleString();
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function updateMetrics(stats) {
    const currentTotal = parseInt(elements.totalFlows.textContent.replace(/,/g, '')) || 0;
    const currentBenign = parseInt(elements.benignFlows.textContent.replace(/,/g, '')) || 0;
    const currentAttacks = parseInt(elements.attackFlows.textContent.replace(/,/g, '')) || 0;

    animateValue(elements.totalFlows, currentTotal, stats.total);
    animateValue(elements.benignFlows, currentBenign, stats.benign);
    animateValue(elements.attackFlows, currentAttacks, stats.attacks);

    if (stats.accuracy !== null && stats.accuracy !== undefined) {
        elements.accuracy.textContent = `${(stats.accuracy * 100).toFixed(1)}%`;
    }
}

function updateRecallBars(stats) {
    if (!stats.recall) return;

    const recallMap = {
        'PortScan': { bar: elements.recallPortscan, value: elements.recallPortscanValue },
        'DDoS': { bar: elements.recallDdos, value: elements.recallDdosValue },
        'DoS Hulk': { bar: elements.recallHulk, value: elements.recallHulkValue },
        'BENIGN': { bar: elements.recallBenign, value: elements.recallBenignValue }
    };

    for (const [label, els] of Object.entries(recallMap)) {
        if (stats.recall[label] !== undefined && els.bar && els.value) {
            const recall = stats.recall[label];
            els.bar.style.width = `${recall * 100}%`;
            els.value.textContent = `${(recall * 100).toFixed(0)}%`;
        }
    }
}

function updateAttackChart(byType) {
    if (!byType || Object.keys(byType).length === 0) {
        elements.attackChart.innerHTML = '<div class="empty-state">Waiting for data...</div>';
        return;
    }

    const maxCount = Math.max(...Object.values(byType));
    elements.attackChart.innerHTML = '';

    const sorted = Object.entries(byType).sort((a, b) => b[1] - a[1]);

    sorted.forEach(([label, count]) => {
        const width = maxCount > 0 ? (count / maxCount) * 100 : 0;
        const isBenign = label === 'BENIGN';

        const row = document.createElement('div');
        row.className = 'chart-bar-row';
        row.innerHTML = `
            <span class="chart-bar-label" title="${label}">${label}</span>
            <div class="chart-bar-container">
                <div class="chart-bar ${isBenign ? 'benign' : 'attack'}" style="width: ${width}%"></div>
            </div>
            <span class="chart-bar-count">${count}</span>
        `;
        elements.attackChart.appendChild(row);
    });
}

function formatTimestamp(ts) {
    const date = new Date(ts);
    return date.toLocaleTimeString('en-US', { hour12: false });
}

function updateEventsTable(events) {
    if (!events.length) {
        elements.eventsTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7">Waiting for network flows...</td>
            </tr>
        `;
        return;
    }

    elements.eventsTableBody.innerHTML = events.map(event => {
        const isBenign = !event.is_attack;
        const severity = event.severity || 'none';
        const confidenceWidth = Math.round(event.prob * 100);

        let rowClass = isBenign ? 'benign-row' : 'attack-row';
        if (severity === 'critical') rowClass = 'critical-row';

        const verified = event.verified;
        let verifiedHtml = '';
        if (verified !== undefined) {
            verifiedHtml = verified
                ? '<span class="verified-badge correct">✓</span>'
                : '<span class="verified-badge incorrect">✗</span>';
        }

        return `
            <tr class="${rowClass}">
                <td>${formatTimestamp(event.ts)}</td>
                <td class="ip-display">${event.src_ip}</td>
                <td class="ip-display">${event.dst_ip || '—'}</td>
                <td><span class="label-badge ${isBenign ? 'benign' : 'attack'}">${event.label}</span></td>
                <td>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${confidenceWidth}px"></div>
                        <span>${(event.prob * 100).toFixed(1)}%</span>
                    </div>
                </td>
                <td><span class="severity-badge ${severity}">${severity.toUpperCase()}</span></td>
                <td>${verifiedHtml}</td>
            </tr>
        `;
    }).join('');
}

function displayPredictionResult(result) {
    if (!result || result.error) {
        elements.predictionResult.innerHTML = `<span class="error">Error: ${result?.error || 'Unknown'}</span>`;
        elements.predictionResult.className = 'prediction-result show';
        return;
    }

    const isBenign = !result.is_attack;
    const confidence = (result.prob * 100).toFixed(1);
    const severity = result.severity || 'none';

    elements.predictionResult.innerHTML = `
        <span class="result-label">${isBenign ? '✅' : '🚨'} ${result.label}</span>
        <span class="result-confidence">${confidence}% confidence</span>
        <span class="result-severity"><span class="severity-badge ${severity}">${severity.toUpperCase()}</span></span>
    `;
    elements.predictionResult.className = `prediction-result show ${isBenign ? 'benign' : 'attack'}`;
}

// ============================================================
// Event Handlers
// ============================================================

// Manual test form submission - collect all 30 features
elements.manualTestForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Start with stored preset features as base
    const features = { ...currentPresetFeatures };

    // Override with current form values
    MODEL_FEATURES.forEach((featureName, index) => {
        const input = document.getElementById(`feature_${index}`);
        if (input) {
            features[featureName] = parseFloat(input.value) || 0;
        }
    });

    console.log(`Submitting ${Object.keys(features).length} features to /api/predict_direct`);
    submitPrediction(features);
});

// Preset buttons - load preset and fill form
elements.presetButtons.addEventListener('click', async (e) => {
    const btn = e.target.closest('.preset-btn');
    if (!btn) return;

    e.preventDefault();
    const presetName = btn.dataset.preset;

    // Visual feedback
    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    // Load preset features into form
    await loadPreset(presetName);
});

// Reset button
elements.resetBtn.addEventListener('click', resetStats);

// ============================================================
// Initialization
// ============================================================

// ============================================================
// Starfield Animation
// ============================================================
class Starfield {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;

        this.ctx = this.canvas.getContext('2d');
        this.stars = [];
        this.speed = 0.5;
        this.warpSpeed = false;

        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.initStars(1000);
        this.animate();
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.cx = this.canvas.width / 2;
        this.cy = this.canvas.height / 2;
    }

    initStars(count) {
        for (let i = 0; i < count; i++) {
            this.stars.push({
                x: Math.random() * this.canvas.width - this.cx,
                y: Math.random() * this.canvas.height - this.cy,
                z: Math.random() * this.canvas.width
            });
        }
    }

    animate() {
        if (!this.ctx) return;

        requestAnimationFrame(() => this.animate());

        this.ctx.fillStyle = this.warpSpeed ? 'rgba(0, 0, 0, 0.2)' : 'rgba(0, 0, 0, 1)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

        const currentSpeed = this.warpSpeed ? 20 : this.speed;

        for (let star of this.stars) {
            star.z -= currentSpeed;

            if (star.z <= 0) {
                star.z = this.canvas.width;
                star.x = Math.random() * this.canvas.width - this.cx;
                star.y = Math.random() * this.canvas.height - this.cy;
            }

            const k = 128.0 / star.z;
            const px = star.x * k + this.cx;
            const py = star.y * k + this.cy;

            if (px >= 0 && px <= this.canvas.width && py >= 0 && py <= this.canvas.height) {
                const size = (1 - star.z / this.canvas.width) * (this.warpSpeed ? 4 : 2);
                const shade = Math.floor((1 - star.z / this.canvas.width) * 255);

                this.ctx.fillStyle = `rgb(${shade}, ${shade}, ${shade})`;
                this.ctx.beginPath();
                this.ctx.arc(px, py, size, 0, Math.PI * 2);
                this.ctx.fill();
            }
        }
    }

    setWarp(enabled) {
        this.warpSpeed = enabled;
    }
}

// ============================================================
// Initialization
// ============================================================

async function init() {
    // Initialize Starfield
    const stars = new Starfield('starfield');

    // Landing Page Transition
    const btnEnter = document.getElementById('btn-enter');
    const landingPage = document.getElementById('landing-page');
    const dashboard = document.getElementById('dashboard');

    if (btnEnter && landingPage && dashboard) {
        btnEnter.addEventListener('click', () => {
            stars.setWarp(true);
            btnEnter.textContent = "ACCESSING MAINFRAME...";

            setTimeout(() => {
                landingPage.style.opacity = '0';
                landingPage.style.transition = 'opacity 1s ease';

                dashboard.style.display = 'block';
                dashboard.style.opacity = '0';
                dashboard.style.transition = 'opacity 1s ease';

                setTimeout(() => {
                    landingPage.style.display = 'none';
                    dashboard.style.opacity = '1';
                    stars.setWarp(false);
                }, 1000);
            }, 1500);
        });
    }

    await loadModelFeatures();
    await fetchStats();
    await fetchEvents();

    setInterval(fetchStats, CONFIG.pollInterval);
    setInterval(fetchEvents, CONFIG.pollInterval);

    console.log('IDS Dashboard initialized with Starlight UI');
}

// Start the app
init();
