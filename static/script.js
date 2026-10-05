/**
 * Anti-Spoofing Packet Verification Virtual Laboratory
 * Academic Simulator Controller
 * Subject: Cryptography & Network Security
 */

// Global Simulator State
const simState = {
    isRunning: false,
    hasAcceptedInitialGenuine: false,
    lastSequenceWatermark: 0,
    activeSection: 'overview'
};

// DOM Initialization
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initMobileDrawer();
});

/* ==========================================================================
   Section Navigation (6 Core Sections)
   ========================================================================== */
function initNavigation() {
    const navButtons = document.querySelectorAll('.menu-btn');
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const sec = btn.getAttribute('data-section');
            if (sec) {
                showSection(sec);
            }
        });
    });

    // Check URL hash if present
    const hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById(hash)) {
        showSection(hash);
    }
}

function showSection(sectionId) {
    const target = document.getElementById(sectionId);
    if (!target) return;

    // Update active button
    document.querySelectorAll('.menu-btn').forEach(btn => {
        if (btn.getAttribute('data-section') === sectionId) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Switch visible view panel
    document.querySelectorAll('.view-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    target.classList.add('active');

    simState.activeSection = sectionId;

    // Scroll smoothly to top
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Close mobile drawer if open
    const sidebar = document.getElementById('cyberSidebar');
    if (sidebar && sidebar.classList.contains('open')) {
        sidebar.classList.remove('open');
    }

    history.replaceState(null, null, `#${sectionId}`);
}

function initMobileDrawer() {
    const toggle = document.getElementById('mobileNavToggle');
    const sidebar = document.getElementById('cyberSidebar');
    if (toggle && sidebar) {
        toggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }
}

/* ==========================================================================
   1. GENUINE PACKET SIMULATION
   ========================================================================== */
async function runGenuineSimulation() {
    if (simState.isRunning) return;
    simState.isRunning = true;

    // Reset visual state before starting
    resetVisualElementsOnly();
    updateArenaMode('GENUINE PACKET TRANSMISSION', 'status-pass');

    // 1. Configure Genuine Packet Data
    const packet = {
        src: '192.168.1.10',
        dest: '192.168.1.20',
        seq: 1001,
        msg: 'Hello Receiver',
        scenario: 'genuine'
    };

    // Calculate real HMAC from backend
    try {
        const createRes = await fetch('/api/create_packet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(packet)
        });
        const created = await createRes.json();
        packet.mac = created.mac;
        packet.mac_preview = created.mac_preview;

        // Display packet at sender and in Packet Information panel
        setDeviceStatus('deviceSender', 'senderStatus', 'Transmitting Packet ➡️', true);
        setDeviceStatus('deviceReceiver', 'receiverStatus', 'Listening', false);
        updatePacketInfoPanel(packet, null);
        updateTravelingPacketUI(packet, false);

        // 2. Animate Packet Travelling SENDER -> NETWORK -> RECEIVER
        await animatePacketTransit(false);

        // 3. Receiver Verification Pipeline
        setDeviceStatus('deviceReceiver', 'receiverStatus', 'Verifying Inbound Packet...', true);
        await runVerificationPipeline(packet, 'genuine');

        simState.hasAcceptedInitialGenuine = true;
        simState.lastSequenceWatermark = 1001;

    } catch (err) {
        console.error('Simulation error:', err);
        alert('Simulation error: ' + err.message);
    } finally {
        simState.isRunning = false;
        setDeviceStatus('deviceSender', 'senderStatus', 'Idle', false);
        setDeviceStatus('deviceReceiver', 'receiverStatus', 'Listening', false);
    }
}

/* ==========================================================================
   2. ATTACK SIMULATIONS (MODIFICATION, IP SPOOFING, REPLAY)
   ========================================================================== */
async function runAttack(attackType) {
    if (simState.isRunning) return;
    simState.isRunning = true;

    try {
        // Special requirement for Replay Attack:
        // Must demonstrate that genuine packet (Seq: 1001) is accepted first!
        if (attackType === 'replay' && !simState.hasAcceptedInitialGenuine) {
            updateArenaMode('STEP 1: ESTABLISHING GENUINE PACKET FIRST', 'status-checking');
            await executeSilentGenuinePacket();
            await delay(800);
        }

        resetVisualElementsOnly();

        // Fetch pre-configured scenario details from Flask backend
        const res = await fetch(`/api/scenario/${attackType}`);
        const scenarioData = await res.json();
        const packet = scenarioData.packet;

        // Setup UI for attack
        if (attackType === 'modified') {
            updateArenaMode('ATTACK: PACKET MODIFICATION', 'status-fail');
            showAttacker('Attacker rewrites message: "Transfer Rs.50000 to attacker"');
            highlightPacketField('fieldMsg');
        } else if (attackType === 'spoofed') {
            updateArenaMode('ATTACK: SOURCE IP SPOOFING', 'status-fail');
            showAttacker('Attacker forges Source IP to: 10.0.0.99');
            highlightPacketField('fieldSrc');
        } else if (attackType === 'replay') {
            updateArenaMode('ATTACK: REPLAY ATTACK (OLD PACKET RESENT)', 'status-fail');
            showAttacker('Attacker resends captured packet (Seq: 1001)');
            highlightPacketField('fieldSeq');
        }

        // Show packet at sender
        setDeviceStatus('deviceSender', 'senderStatus', 'Dispatched Packet', false);
        updatePacketInfoPanel(packet, scenarioData.highlight_field);
        updateTravelingPacketUI(packet, true);

        // Animate packet intercepted by Attacker then delivered to Receiver
        await animatePacketTransit(true);

        // Run Receiver Verification Pipeline
        setDeviceStatus('deviceReceiver', 'receiverStatus', 'Running Security Verification...', true);
        await runVerificationPipeline(packet, attackType);

    } catch (err) {
        console.error('Attack simulation error:', err);
        alert('Attack simulation error: ' + err.message);
    } finally {
        simState.isRunning = false;
        setDeviceStatus('deviceSender', 'senderStatus', 'Idle', false);
        setDeviceStatus('deviceReceiver', 'receiverStatus', 'Listening', false);
    }
}

/**
 * Silently runs genuine packet flow for Replay demonstration prerequisite
 */
async function executeSilentGenuinePacket() {
    const genuinePkt = {
        src: '192.168.1.10',
        dest: '192.168.1.20',
        seq: 1001,
        msg: 'Hello Receiver'
    };
    const cRes = await fetch('/api/create_packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(genuinePkt)
    });
    const created = await cRes.json();
    genuinePkt.mac = created.mac;
    genuinePkt.scenario = 'genuine';

    updatePacketInfoPanel(genuinePkt, null);
    updateTravelingPacketUI(genuinePkt, false);

    await animatePacketTransit(false);
    await runVerificationPipeline(genuinePkt, 'genuine');
    simState.hasAcceptedInitialGenuine = true;
    simState.lastSequenceWatermark = 1001;
}

/* ==========================================================================
   3. VERIFICATION PIPELINE (One-by-One Stage Display)
   ========================================================================== */
async function runVerificationPipeline(packet, scenarioType) {
    const statusAuth = document.getElementById('statusAuth');
    const statusIntegrity = document.getElementById('statusIntegrity');
    const statusSeq = document.getElementById('statusSeq');

    // Reset check statuses to checking
    setCheckStatus(statusAuth, 'CHECKING...', 'status-checking');
    await delay(550);

    // Call verify endpoint on backend
    const verifyRes = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(packet)
    });
    const result = await verifyRes.json();

    // 1. Authentication Check
    if (result.authentication === 'PASS') {
        setCheckStatus(statusAuth, 'PASS', 'status-pass');
    } else {
        setCheckStatus(statusAuth, 'FAIL', 'status-fail');
    }

    // 2. Integrity Check
    setCheckStatus(statusIntegrity, 'CHECKING...', 'status-checking');
    await delay(550);

    if (result.integrity === 'PASS') {
        setCheckStatus(statusIntegrity, 'PASS', 'status-pass');
    } else {
        setCheckStatus(statusIntegrity, 'FAIL', 'status-fail');
    }

    // 3. Sequence Number Check
    setCheckStatus(statusSeq, 'CHECKING...', 'status-checking');
    await delay(550);

    if (result.sequence_valid === 'VALID') {
        setCheckStatus(statusSeq, 'VALID', 'status-pass');
    } else {
        setCheckStatus(statusSeq, 'FAIL', 'status-fail');
    }

    // 4. Final Verdict Display
    await delay(400);
    renderFinalVerdict(result);
}

function setCheckStatus(el, text, className) {
    if (!el) return;
    el.className = `step-status ${className}`;
    el.textContent = text;
}

function renderFinalVerdict(result) {
    const banner = document.getElementById('verdictBanner');
    const title = document.getElementById('verdictTitle');
    const sub = document.getElementById('verdictSub');
    const reasonBox = document.getElementById('verdictReason');

    if (result.accepted) {
        banner.className = 'verdict-banner accepted';
        title.textContent = '✓ PACKET ACCEPTED';
        sub.textContent = 'Authentication: PASS  •  Integrity: PASS  •  Sequence Number: VALID';
        reasonBox.style.display = 'none';
        document.getElementById('infoStatus').textContent = 'VERIFIED & ACCEPTED';
        document.getElementById('infoStatus').style.color = '#10b981';
    } else {
        banner.className = 'verdict-banner rejected';
        title.textContent = '✗ PACKET REJECTED';
        sub.textContent = `Authentication: ${result.authentication}  •  Integrity: ${result.integrity}  •  Sequence Number: ${result.sequence_valid}`;
        
        reasonBox.style.display = 'inline-block';
        reasonBox.textContent = `Reason: "${result.reason}"`;
        document.getElementById('infoStatus').textContent = 'REJECTED';
        document.getElementById('infoStatus').style.color = '#ef4444';
    }
}

/* ==========================================================================
   4. ANIMATION & PACKET VISUALIZATION
   ========================================================================== */
function animatePacketTransit(isAttack) {
    return new Promise(resolve => {
        const tp = document.getElementById('travelingPacket');
        if (!tp) return resolve();

        // Reset to Sender
        tp.style.transition = 'none';
        tp.style.left = '5%';
        void tp.offsetWidth; // Force reflow

        if (isAttack) {
            // SENDER -> ATTACKER
            tp.style.transition = 'left 0.9s cubic-bezier(0.25, 1, 0.5, 1)';
            tp.style.left = '45%';

            setTimeout(() => {
                tp.classList.add('tampered');
                // ATTACKER -> RECEIVER
                tp.style.transition = 'left 1.1s cubic-bezier(0.25, 1, 0.5, 1)';
                tp.style.left = '80%';
                setTimeout(resolve, 1150);
            }, 950);

        } else {
            // SENDER -> RECEIVER direct smooth transit
            tp.classList.remove('tampered');
            tp.style.transition = 'left 1.8s cubic-bezier(0.4, 0, 0.2, 1)';
            tp.style.left = '80%';
            setTimeout(resolve, 1850);
        }
    });
}

function updateTravelingPacketUI(packet, isTampered) {
    document.getElementById('tpSrc').textContent = packet.src;
    document.getElementById('tpDest').textContent = packet.dest;
    document.getElementById('tpSeq').textContent = packet.seq;
    document.getElementById('tpMsg').textContent = packet.msg;
    document.getElementById('tpHash').textContent = packet.mac_preview || 'Computed MAC';

    const tp = document.getElementById('travelingPacket');
    tp.style.left = '5%';
    if (isTampered) {
        tp.classList.add('tampered');
    } else {
        tp.classList.remove('tampered');
    }
}

function updatePacketInfoPanel(packet, highlightField) {
    document.getElementById('infoSrc').textContent = packet.src;
    document.getElementById('infoDest').textContent = packet.dest;
    document.getElementById('infoSeq').textContent = packet.seq;
    document.getElementById('infoMsg').textContent = packet.msg;
    document.getElementById('infoVerif').textContent = packet.mac_preview || 'Generated via secret-key verification';
    document.getElementById('infoStatus').textContent = 'In Transit';
    document.getElementById('infoStatus').style.color = '#00f0ff';

    // Clear previous field highlights
    clearPacketHighlights();

    if (highlightField === 'src') {
        highlightPacketField('fieldSrc');
    } else if (highlightField === 'msg') {
        highlightPacketField('fieldMsg');
    } else if (highlightField === 'seq') {
        highlightPacketField('fieldSeq');
    }
}

function highlightPacketField(elementId) {
    const el = document.getElementById(elementId);
    if (el) el.classList.add('highlight-tampered');
}

function clearPacketHighlights() {
    ['fieldSrc', 'fieldMsg', 'fieldSeq'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove('highlight-tampered');
    });
}

function showAttacker(actionText) {
    const dev = document.getElementById('deviceAttacker');
    const txt = document.getElementById('attackerActionText');
    if (dev && txt) {
        txt.textContent = actionText;
        dev.style.display = 'flex';
    }
}

function hideAttacker() {
    const dev = document.getElementById('deviceAttacker');
    if (dev) dev.style.display = 'none';
}

function setDeviceStatus(deviceId, statusId, text, isActive) {
    const dev = document.getElementById(deviceId);
    const stat = document.getElementById(statusId);
    if (stat) stat.textContent = text;
    if (dev) {
        if (isActive) {
            dev.classList.add('active-node');
        } else {
            dev.classList.remove('active-node');
        }
    }
}

function updateArenaMode(modeText, badgeClass) {
    const badge = document.getElementById('arenaModeBadge');
    if (badge) {
        badge.textContent = modeText;
        badge.className = `arena-mode-badge ${badgeClass}`;
    }
}

function resetVisualElementsOnly() {
    hideAttacker();
    clearPacketHighlights();

    // Reset pipeline step statuses to WAITING
    setCheckStatus(document.getElementById('statusAuth'), 'WAITING', 'status-waiting');
    setCheckStatus(document.getElementById('statusIntegrity'), 'WAITING', 'status-waiting');
    setCheckStatus(document.getElementById('statusSeq'), 'WAITING', 'status-waiting');

    // Reset verdict banner
    const banner = document.getElementById('verdictBanner');
    banner.className = 'verdict-banner';
    document.getElementById('verdictTitle').textContent = 'Awaiting Simulation';
    document.getElementById('verdictSub').textContent = 'Click "START GENUINE PACKET" or choose an attack scenario.';
    document.getElementById('verdictReason').style.display = 'none';

    // Reset traveling packet position
    const tp = document.getElementById('travelingPacket');
    if (tp) {
        tp.style.transition = 'none';
        tp.style.left = '5%';
        tp.classList.remove('tampered');
    }
}

/* ==========================================================================
   5. RESET SIMULATION (Complete State & Backend Reset)
   ========================================================================== */
async function resetSimulation() {
    try {
        await fetch('/api/reset', { method: 'POST' });
        simState.hasAcceptedInitialGenuine = false;
        simState.lastSequenceWatermark = 0;
        simState.isRunning = false;

        resetVisualElementsOnly();
        updateArenaMode('SIMULATION RESET (READY)', 'status-waiting');

        // Reset info panel
        document.getElementById('infoSrc').textContent = '192.168.1.10';
        document.getElementById('infoDest').textContent = '192.168.1.20';
        document.getElementById('infoSeq').textContent = '1001';
        document.getElementById('infoMsg').textContent = 'Hello Receiver';
        document.getElementById('infoVerif').textContent = 'Generated via secret-key verification';
        document.getElementById('infoStatus').textContent = 'Awaiting Simulation';
        document.getElementById('infoStatus').style.color = '#94a3b8';

        setDeviceStatus('deviceSender', 'senderStatus', 'Idle', false);
        setDeviceStatus('deviceReceiver', 'receiverStatus', 'Listening', false);

        alert('Simulator state reset. Packet sequence reset to 0.');
    } catch (err) {
        console.error('Reset error:', err);
    }
}

function delay(ms) {
    return new Promise(res => setTimeout(res, ms));
}
