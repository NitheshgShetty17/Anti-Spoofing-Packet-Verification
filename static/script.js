/**
 * Implementation of Anti-Spoofing Packet Verification Virtual Laboratory
 * Academic Simulator Controller
 * Subject: Cryptography & Network Security
 */

// Global Simulator State
const simState = {
    isRunning: false,
    hasAcceptedInitialGenuine: false,
    lastSequenceWatermark: 0,
    lastAcceptedPacket: null,
    activeSection: 'overview'
};

// DOM Initialization
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initMobileDrawer();
    initInputLiveSync();
});

/* ==========================================================================
   Section Navigation (7 Core Sections)
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
   Live Device Track Synchronization
   ========================================================================== */
function initInputLiveSync() {
    const srcInput = document.getElementById('inputSenderIp');
    const destInput = document.getElementById('inputReceiverIp');

    if (srcInput) {
        srcInput.addEventListener('input', () => {
            const dev = document.getElementById('deviceSender');
            if (dev) {
                const ipLabel = dev.querySelector('.device-ip');
                if (ipLabel) ipLabel.textContent = srcInput.value.trim() || '192.168.1.10';
            }
            hideInputAlert();
        });
    }

    if (destInput) {
        destInput.addEventListener('input', () => {
            const dev = document.getElementById('deviceReceiver');
            if (dev) {
                const ipLabel = dev.querySelector('.device-ip');
                if (ipLabel) ipLabel.textContent = destInput.value.trim() || '192.168.1.20';
            }
            hideInputAlert();
        });
    }

    const seqInput = document.getElementById('inputSeqNum');
    if (seqInput) seqInput.addEventListener('input', hideInputAlert);

    const msgInput = document.getElementById('inputMessage');
    if (msgInput) msgInput.addEventListener('input', hideInputAlert);
}

function hideInputAlert() {
    const alertBox = document.getElementById('inputAlertBox');
    if (alertBox) alertBox.style.display = 'none';
}

/* ==========================================================================
   Input Validation Helper
   ========================================================================== */
function isValidIPv4(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
        if (!/^\d+$/.test(part)) return false;
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255 && (part === '0' || !part.startsWith('0'));
    });
}

function getAndValidateUserInputs() {
    const srcInput = document.getElementById('inputSenderIp');
    const destInput = document.getElementById('inputReceiverIp');
    const seqInput = document.getElementById('inputSeqNum');
    const msgInput = document.getElementById('inputMessage');
    const alertBox = document.getElementById('inputAlertBox');
    const alertMsg = document.getElementById('inputAlertMsg');

    const src = srcInput ? srcInput.value.trim() : '';
    const dest = destInput ? destInput.value.trim() : '';
    const seqStr = seqInput ? seqInput.value.trim() : '';
    const msg = msgInput ? msgInput.value.trim() : '';

    // Clear previous input error borders
    [srcInput, destInput, seqInput, msgInput].forEach(inp => {
        if (inp) inp.classList.remove('input-field-error');
    });

    function showError(message, focusElement) {
        if (alertBox && alertMsg) {
            alertMsg.textContent = message;
            alertBox.style.display = 'flex';
        }
        if (focusElement) {
            focusElement.classList.add('input-field-error');
            focusElement.focus();
        }
        return null;
    }

    // 1. Sender IP validation
    if (!src) {
        return showError('Please enter a Sender IP address (e.g. 192.168.1.10).', srcInput);
    }
    if (!isValidIPv4(src)) {
        return showError(`"${src}" is not a valid IPv4 address. Please use standard format X.X.X.X (0-255).`, srcInput);
    }

    // 2. Receiver IP validation
    if (!dest) {
        return showError('Please enter a Receiver IP address (e.g. 192.168.1.20).', destInput);
    }
    if (!isValidIPv4(dest)) {
        return showError(`"${dest}" is not a valid IPv4 address. Please use standard format X.X.X.X (0-255).`, destInput);
    }

    // 3. Sequence Number validation
    if (!seqStr) {
        return showError('Please enter a Sequence Number (e.g. 1001).', seqInput);
    }
    const seq = parseInt(seqStr, 10);
    if (isNaN(seq) || seq <= 0) {
        return showError('Sequence Number must be a positive integer greater than 0.', seqInput);
    }

    // 4. Message validation
    if (!msg) {
        return showError('Please enter a Message payload (e.g. Hello Receiver).', msgInput);
    }

    // Everything valid
    if (alertBox) alertBox.style.display = 'none';
    return { src, dest, seq, msg };
}

/* ==========================================================================
   Simulator Button Selection Manager
   ========================================================================== */
const SIM_OPTION_BUTTON_IDS = [
    'btnRunSimulation',
    'btnGenuine',
    'btnModAttack',
    'btnSpoofAttack',
    'btnReplayAttack'
];

function setSelectedSimulationButton(selectedId) {
    SIM_OPTION_BUTTON_IDS.forEach(id => {
        const btn = document.getElementById(id);
        if (btn) {
            if (id === selectedId) {
                btn.classList.add('selected');
            } else {
                btn.classList.remove('selected');
            }
        }
    });
}

function clearSelectedSimulationButtons() {
    SIM_OPTION_BUTTON_IDS.forEach(id => {
        const btn = document.getElementById(id);
        if (btn) {
            btn.classList.remove('selected');
        }
    });
}

/* ==========================================================================
   CORE UNIFIED SIMULATOR CONTROLLER (OPERATES ON LIVE USER INPUT)
   ========================================================================== */
async function runUserSimulation(scenarioType) {
    if (simState.isRunning) return;

    // Validate user inputs before proceeding
    const userInput = getAndValidateUserInputs();
    if (!userInput) return;

    const { src, dest, seq, msg } = userInput;

    // Update button highlight
    const btnMap = {
        'genuine': 'btnRunSimulation',
        'modified': 'btnModAttack',
        'spoofed': 'btnSpoofAttack',
        'replay': 'btnReplayAttack'
    };
    setSelectedSimulationButton(btnMap[scenarioType] || 'btnRunSimulation');
    simState.isRunning = true;

    // Sync node device IP badges on track
    const sDev = document.getElementById('deviceSender');
    const rDev = document.getElementById('deviceReceiver');
    if (sDev) {
        const ipSpan = sDev.querySelector('.device-ip');
        if (ipSpan) ipSpan.textContent = src;
    }
    if (rDev) {
        const ipSpan = rDev.querySelector('.device-ip');
        if (ipSpan) ipSpan.textContent = dest;
    }

    try {
        if (scenarioType === 'genuine') {
            await executeGenuineScenario(src, dest, seq, msg);
        } else if (scenarioType === 'modified') {
            await executeModificationScenario(src, dest, seq, msg);
        } else if (scenarioType === 'spoofed') {
            await executeSpoofingScenario(src, dest, seq, msg);
        } else if (scenarioType === 'replay') {
            await executeReplayScenario(src, dest, seq, msg);
        }
    } catch (err) {
        console.error('Simulation execution error:', err);
        alert('Simulation error: ' + err.message);
    } finally {
        simState.isRunning = false;
        setDeviceStatus('deviceSender', 'senderStatus', 'Idle', false);
        setDeviceStatus('deviceReceiver', 'receiverStatus', 'Listening', false);
    }
}

// Aliases for backwards compatibility with any existing calls
function runGenuineSimulation() {
    return runUserSimulation('genuine');
}

function runAttack(attackType) {
    return runUserSimulation(attackType);
}

/* ==========================================================================
   SCENARIO 1: GENUINE PACKET (AUTHENTIC TRANSMISSION)
   ========================================================================== */
async function executeGenuineScenario(src, dest, seq, msg) {
    resetVisualElementsOnly();
    updateArenaMode('GENUINE PACKET TRANSMISSION', 'status-pass');

    // 1. Generate real HMAC using user's packet details on backend
    const createRes = await fetch('/api/create_packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ src, dest, seq, msg })
    });
    const created = await createRes.json();

    const packet = {
        src: created.src,
        dest: created.dest,
        seq: created.seq,
        msg: created.msg,
        mac: created.mac,
        mac_preview: created.mac_preview,
        scenario: 'genuine'
    };

    // 2. Display packet at sender and in Packet Information panel
    setDeviceStatus('deviceSender', 'senderStatus', 'Transmitting Packet ➡️', true);
    setDeviceStatus('deviceReceiver', 'receiverStatus', 'Listening', false);
    updatePacketInfoPanel(packet, null);
    updateTravelingPacketUI(packet, false);

    // 3. Animate packet smoothly across the network track
    await animatePacketTransit(false);

    // 4. Receiver verifies the packet
    setDeviceStatus('deviceReceiver', 'receiverStatus', 'Verifying Inbound Packet...', true);
    await runVerificationPipeline(packet, 'genuine');

    simState.hasAcceptedInitialGenuine = true;
    simState.lastSequenceWatermark = seq;
    simState.lastAcceptedPacket = { ...packet };
}

/* ==========================================================================
   SCENARIO 2: PACKET MODIFICATION ATTACK
   ========================================================================== */
async function executeModificationScenario(src, dest, seq, msg) {
    resetVisualElementsOnly();
    updateArenaMode('ATTACK: PACKET MODIFICATION', 'status-fail');

    // 1. Attacker intercepts genuine packet created from user input
    const createRes = await fetch('/api/create_packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ src, dest, seq, msg })
    });
    const legitimate = await createRes.json();

    // Attacker modifies the message payload but keeps the original HMAC
    const tamperedMsg = (msg === 'Hello Receiver')
        ? 'Transfer Rs.50000 to attacker'
        : `${msg} [MODIFIED: Rs.50000 transferred to attacker]`;

    const packet = {
        src: legitimate.src,
        dest: legitimate.dest,
        seq: legitimate.seq,
        msg: tamperedMsg,
        mac: legitimate.mac, // Original HMAC kept!
        mac_preview: legitimate.mac_preview,
        scenario: 'modified'
    };

    // 2. Setup attacker node and field highlight
    showAttacker(`Attacker rewrites message: "${tamperedMsg}"`);
    setDeviceStatus('deviceSender', 'senderStatus', 'Dispatched Packet', false);
    updatePacketInfoPanel(packet, 'msg');
    updateTravelingPacketUI(packet, true);

    // 3. Animate transit through attacker node
    await animatePacketTransit(true);

    // 4. Receiver verification pipeline (tampering detected by HMAC mismatch)
    setDeviceStatus('deviceReceiver', 'receiverStatus', 'Running Security Verification...', true);
    await runVerificationPipeline(packet, 'modified');
}

/* ==========================================================================
   SCENARIO 3: SOURCE IP SPOOFING ATTACK
   ========================================================================== */
async function executeSpoofingScenario(src, dest, seq, msg) {
    resetVisualElementsOnly();
    updateArenaMode('ATTACK: SOURCE IP SPOOFING', 'status-fail');

    // 1. Generate legitimate HMAC for user's packet
    const createRes = await fetch('/api/create_packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ src, dest, seq, msg })
    });
    const legitimate = await createRes.json();

    // Attacker forges the source IP to impersonate another machine
    const spoofedSrc = (src === '10.0.0.99') ? '172.16.0.50' : '10.0.0.99';

    const packet = {
        src: spoofedSrc,
        dest: legitimate.dest,
        seq: legitimate.seq,
        msg: legitimate.msg,
        mac: legitimate.mac, // Original HMAC kept!
        mac_preview: legitimate.mac_preview,
        scenario: 'spoofed'
    };

    // 2. Setup attacker node and field highlight
    showAttacker(`Attacker forges Source IP from ${src} to ${spoofedSrc}`);
    setDeviceStatus('deviceSender', 'senderStatus', 'Dispatched Packet', false);
    updatePacketInfoPanel(packet, 'src');
    updateTravelingPacketUI(packet, true);

    // 3. Animate transit through attacker node
    await animatePacketTransit(true);

    // 4. Receiver verification pipeline (spoofing detected by HMAC mismatch)
    setDeviceStatus('deviceReceiver', 'receiverStatus', 'Running Security Verification...', true);
    await runVerificationPipeline(packet, 'spoofed');
}

/* ==========================================================================
   SCENARIO 4: REPLAY ATTACK (RESENDING PREVIOUS PACKET)
   ========================================================================== */
async function executeReplayScenario(src, dest, seq, msg) {
    // Replay attack requires that genuine packet (with this seq) was accepted first!
    if (!simState.hasAcceptedInitialGenuine || simState.lastSequenceWatermark !== seq) {
        updateArenaMode('STEP 1: ESTABLISHING INITIAL GENUINE PACKET (Seq: ' + seq + ')', 'status-checking');
        await executeSilentUserPacket(src, dest, seq, msg);
        await delay(800);
    }

    resetVisualElementsOnly();
    updateArenaMode('STEP 2: ATTACKER REPLAYS CAPTURED PACKET (Seq: ' + seq + ')', 'status-fail');

    // The attacker captured the exact legitimate packet previously accepted
    const replayedPacket = {
        src: src,
        dest: dest,
        seq: seq, // Old sequence number already processed by receiver!
        msg: msg,
        mac: simState.lastAcceptedPacket ? simState.lastAcceptedPacket.mac : '',
        mac_preview: simState.lastAcceptedPacket ? simState.lastAcceptedPacket.mac_preview : '',
        scenario: 'replay'
    };

    // Attacker node notification
    showAttacker(`Attacker captures & resends packet with old Sequence: ${seq}`);
    setDeviceStatus('deviceSender', 'senderStatus', 'Dispatched Packet', false);
    updatePacketInfoPanel(replayedPacket, 'seq');
    updateTravelingPacketUI(replayedPacket, true);

    // Animate transit
    await animatePacketTransit(true);

    // Receiver verification pipeline (replay detected because seq <= last_sequence)
    setDeviceStatus('deviceReceiver', 'receiverStatus', 'Checking Replay Protection...', true);
    await runVerificationPipeline(replayedPacket, 'replay');
}

/**
 * Silently establishes genuine packet baseline with user values for Replay test
 */
async function executeSilentUserPacket(src, dest, seq, msg) {
    const cRes = await fetch('/api/create_packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ src, dest, seq, msg })
    });
    const created = await cRes.json();
    const genuinePkt = {
        src: created.src,
        dest: created.dest,
        seq: created.seq,
        msg: created.msg,
        mac: created.mac,
        mac_preview: created.mac_preview,
        scenario: 'genuine'
    };

    updatePacketInfoPanel(genuinePkt, null);
    updateTravelingPacketUI(genuinePkt, false);

    await animatePacketTransit(false);
    await runVerificationPipeline(genuinePkt, 'genuine');

    simState.hasAcceptedInitialGenuine = true;
    simState.lastSequenceWatermark = seq;
    simState.lastAcceptedPacket = { ...genuinePkt };
}

/* ==========================================================================
   VERIFICATION PIPELINE (Sequential Stage Verification Display)
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
        const infoStatus = document.getElementById('infoStatus');
        if (infoStatus) {
            infoStatus.textContent = 'VERIFIED & ACCEPTED';
            infoStatus.style.color = '#15803d'; // Rich green
        }
    } else {
        banner.className = 'verdict-banner rejected';
        title.textContent = '✗ PACKET REJECTED';
        sub.textContent = `Authentication: ${result.authentication}  •  Integrity: ${result.integrity}  •  Sequence Number: ${result.sequence_valid}`;
        
        reasonBox.style.display = 'inline-block';
        reasonBox.textContent = `Reason: "${result.reason}"`;
        const infoStatus = document.getElementById('infoStatus');
        if (infoStatus) {
            infoStatus.textContent = 'REJECTED';
            infoStatus.style.color = '#d97706'; // Amber/orange
        }
    }
}

/* ==========================================================================
   ANIMATION & PACKET VISUALIZATION
   ========================================================================== */
function animatePacketTransit(isAttack) {
    return new Promise(resolve => {
        const tp = document.getElementById('travelingPacket');
        if (!tp) return resolve();

        // Reset to Sender position
        tp.style.transition = 'none';
        tp.style.left = '5%';
        void tp.offsetWidth; // Force DOM reflow

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
    const tpSrc = document.getElementById('tpSrc');
    const tpDest = document.getElementById('tpDest');
    const tpSeq = document.getElementById('tpSeq');
    const tpMsg = document.getElementById('tpMsg');
    const tpHash = document.getElementById('tpHash');

    if (tpSrc) tpSrc.textContent = packet.src;
    if (tpDest) tpDest.textContent = packet.dest;
    if (tpSeq) tpSeq.textContent = packet.seq;
    if (tpMsg) tpMsg.textContent = packet.msg;
    if (tpHash) tpHash.textContent = packet.mac_preview || (packet.mac ? packet.mac.slice(0, 16) + '...' : 'Computed MAC');

    const tp = document.getElementById('travelingPacket');
    if (tp) {
        tp.style.left = '5%';
        if (isTampered) {
            tp.classList.add('tampered');
        } else {
            tp.classList.remove('tampered');
        }
    }
}

function updatePacketInfoPanel(packet, highlightField) {
    const infoSrc = document.getElementById('infoSrc');
    const infoDest = document.getElementById('infoDest');
    const infoSeq = document.getElementById('infoSeq');
    const infoMsg = document.getElementById('infoMsg');
    const infoVerif = document.getElementById('infoVerif');
    const infoStatus = document.getElementById('infoStatus');

    if (infoSrc) infoSrc.textContent = packet.src;
    if (infoDest) infoDest.textContent = packet.dest;
    if (infoSeq) infoSeq.textContent = packet.seq;
    if (infoMsg) infoMsg.textContent = packet.msg;
    if (infoVerif) infoVerif.textContent = packet.mac_preview || (packet.mac ? packet.mac.slice(0, 16) + '...' + packet.mac.slice(-8) : 'Generated via secret-key verification');
    if (infoStatus) {
        infoStatus.textContent = 'In Transit';
        infoStatus.style.color = '#0284c7'; // Blue accent
    }

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
    if (banner) banner.className = 'verdict-banner';
    const vTitle = document.getElementById('verdictTitle');
    const vSub = document.getElementById('verdictSub');
    const vReason = document.getElementById('verdictReason');

    if (vTitle) vTitle.textContent = 'Awaiting Simulation';
    if (vSub) vSub.textContent = 'Enter packet details above and click "CREATE PACKET / RUN SIMULATION" or choose an attack scenario.';
    if (vReason) vReason.style.display = 'none';

    // Reset traveling packet position
    const tp = document.getElementById('travelingPacket');
    if (tp) {
        tp.style.transition = 'none';
        tp.style.left = '5%';
        tp.classList.remove('tampered');
    }
}

/* ==========================================================================
   RESET SIMULATION (Complete State & Backend Reset)
   ========================================================================== */
async function resetSimulation() {
    try {
        clearSelectedSimulationButtons();
        await fetch('/api/reset', { method: 'POST' });
        simState.hasAcceptedInitialGenuine = false;
        simState.lastSequenceWatermark = 0;
        simState.lastAcceptedPacket = null;
        simState.isRunning = false;

        resetVisualElementsOnly();
        hideInputAlert();
        updateArenaMode('SIMULATION RESET (READY)', 'status-waiting');

        // Reset info panel
        const infoSrc = document.getElementById('infoSrc');
        const infoDest = document.getElementById('infoDest');
        const infoSeq = document.getElementById('infoSeq');
        const infoMsg = document.getElementById('infoMsg');
        const infoVerif = document.getElementById('infoVerif');
        const infoStatus = document.getElementById('infoStatus');

        const srcInput = document.getElementById('inputSenderIp');
        const destInput = document.getElementById('inputReceiverIp');
        const seqInput = document.getElementById('inputSeqNum');
        const msgInput = document.getElementById('inputMessage');

        const curSrc = srcInput ? srcInput.value.trim() : '192.168.1.10';
        const curDest = destInput ? destInput.value.trim() : '192.168.1.20';
        const curSeq = seqInput ? seqInput.value.trim() : '1001';
        const curMsg = msgInput ? msgInput.value.trim() : 'Hello Receiver';

        if (infoSrc) infoSrc.textContent = curSrc;
        if (infoDest) infoDest.textContent = curDest;
        if (infoSeq) infoSeq.textContent = curSeq;
        if (infoMsg) infoMsg.textContent = curMsg;
        if (infoVerif) infoVerif.textContent = 'Generated via secret-key verification';
        if (infoStatus) {
            infoStatus.textContent = 'Awaiting Simulation';
            infoStatus.style.color = '#000000';
        }

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
