/* USX Migrator Assistant — Client-side JS */

function copyToClipboard(btn) {
    const block = btn.closest('.command-block');
    const code = block.querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        const orig = btn.textContent;
        btn.textContent = '✓ Copied';
        setTimeout(() => { btn.textContent = orig; }, 2000);
    });
}

function downloadScript(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'usx-migration-fix.sh';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function toggleChecklist(workspace, key, checked) {
    fetch('/checklist/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspace: workspace, key: key, checked: checked })
    });
}

function showLoading(message) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.querySelector('.loading-message').textContent = message || 'Working...';
        overlay.style.display = 'flex';
    }
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

// Wizard: track current finding index
let currentFindingIndex = 0;

function showFinding(index) {
    const findings = document.querySelectorAll('.wizard-finding');
    if (index < 0 || index >= findings.length) return;
    findings.forEach((f, i) => {
        f.style.display = i === index ? 'block' : 'none';
    });
    currentFindingIndex = index;
    document.getElementById('wizard-progress').textContent =
        `${index + 1} of ${findings.length}`;

    // Toggle nav buttons
    const prevBtn = document.getElementById('wizard-prev');
    const nextBtn = document.getElementById('wizard-next');
    if (prevBtn) prevBtn.disabled = index === 0;
    if (nextBtn) nextBtn.textContent = index === findings.length - 1 ? 'Finish' : 'Next →';
}

function wizardNext() {
    const findings = document.querySelectorAll('.wizard-finding');
    if (currentFindingIndex < findings.length - 1) {
        showFinding(currentFindingIndex + 1);
    } else {
        window.location.href = '/';
    }
}

function wizardPrev() {
    if (currentFindingIndex > 0) {
        showFinding(currentFindingIndex - 1);
    }
}

function markAddressed(findingId) {
    fetch('/finding/addressed', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: findingId })
    }).then(() => {
        const badge = document.getElementById('badge-' + findingId);
        if (badge) {
            badge.textContent = '✓ Addressed';
            badge.className = 'badge bg-success';
        }
    });
}
