// Enhanced app.js - Modern client logic for the Secure Compiler Assistant
const editor = document.getElementById('editor');
const analyzeBtn = document.getElementById('analyzeBtn');
const confSlider = document.getElementById('minConfidence');
const confVal = document.getElementById('confVal');
const optimizeChk = document.getElementById('optimize');
const runChk = document.getElementById('runProgram');
const riskBanner = document.getElementById('riskBanner');
const findingsEl = document.getElementById('findings');
const errorsEl = document.getElementById('errors');
const irEl = document.getElementById('ir');
const astEl = document.getElementById('ast');
const outputEl = document.getElementById('output');
const dlAst = document.getElementById('dlAst');
const dlIr = document.getElementById('dlIr');
const themeToggle = document.getElementById('themeToggle');
const mobileMenuToggle = document.getElementById('mobileMenuToggle');
const leftPane = document.getElementById('leftPane');
const loadingOverlay = document.getElementById('loadingOverlay');
const toastContainer = document.getElementById('toastContainer');
const lineCount = document.getElementById('lineCount');
const charCount = document.getElementById('charCount');
let lastResults = null;

// Theme management
let currentTheme = localStorage.getItem('theme') || 'dark';
document.documentElement.setAttribute('data-theme', currentTheme);

if (themeToggle) {
  themeToggle.innerHTML = `<span class="theme-icon">${currentTheme === 'dark' ? '☀️' : '🌙'}</span>`;
  themeToggle.setAttribute('aria-label', `Switch to ${currentTheme === 'dark' ? 'light' : 'dark'} theme`);
  
  themeToggle.addEventListener('click', () => {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    localStorage.setItem('theme', currentTheme);
    themeToggle.innerHTML = `<span class="theme-icon">${currentTheme === 'dark' ? '☀️' : '🌙'}</span>`;
    themeToggle.setAttribute('aria-label', `Switch to ${currentTheme === 'dark' ? 'light' : 'dark'} theme`);
    showToast(`Switched to ${currentTheme} theme`, 'success');
  });
}

// Mobile menu toggle
if (mobileMenuToggle && leftPane) {
  mobileMenuToggle.addEventListener('click', () => {
    mobileMenuToggle.classList.toggle('active');
    leftPane.classList.toggle('mobile-open');
  });
}

// Toast notification system
function showToast(message, type = 'info', duration = 3000) {
  if (!toastContainer) return;
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <div style="display: flex; align-items: center; gap: 0.5rem;">
      <span style="font-size: 1.2rem;">${type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️'}</span>
      <span>${message}</span>
    </div>
  `;
  
  toastContainer.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 300ms ease forwards';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, duration);
}

// Editor statistics and auto-save
let autoSaveTimeout;
function updateEditorStats() {
  if (!editor || !lineCount || !charCount) return;
  
  const text = editor.value;
  const lines = text.split('\n').length;
  const chars = text.length;
  
  lineCount.textContent = `Lines: ${lines}`;
  charCount.textContent = `Characters: ${chars}`;
  
  // Auto-save to localStorage
  clearTimeout(autoSaveTimeout);
  autoSaveTimeout = setTimeout(() => {
    localStorage.setItem('editor-content', text);
  }, 1000);
}

// Load saved content
if (editor) {
  const saved = localStorage.getItem('editor-content');
  if (saved && !editor.value) {
    editor.value = saved;
  }
  
  editor.addEventListener('input', updateEditorStats);
  editor.addEventListener('keydown', handleEditorKeyboard);
  updateEditorStats();
}

// Enhanced keyboard shortcuts
function handleEditorKeyboard(e) {
  // Ctrl/Cmd + S to analyze
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    if (analyzeBtn && !analyzeBtn.disabled) {
      analyzeBtn.click();
    }
  }
  
  // Tab handling for better indentation
  if (e.key === 'Tab') {
    e.preventDefault();
    const start = editor.selectionStart;
    const end = editor.selectionEnd;
    const value = editor.value;
    
    if (e.shiftKey) {
      // Shift+Tab: unindent
      const lines = value.substring(0, start).split('\n');
      const currentLine = lines[lines.length - 1];
      if (currentLine.startsWith('  ')) {
        const newStart = start - 2;
        editor.value = value.substring(0, newStart) + value.substring(start);
        editor.selectionStart = editor.selectionEnd = newStart;
      }
    } else {
      // Tab: indent
      editor.value = value.substring(0, start) + '  ' + value.substring(end);
      editor.selectionStart = editor.selectionEnd = start + 2;
    }
    updateEditorStats();
  }
}

confSlider.addEventListener('input', () => {
  confVal.textContent = Number(confSlider.value).toFixed(2);
});

// Copy output
const copyOutputBtn = document.getElementById('copyOutput');
if (copyOutputBtn) {
  copyOutputBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(outputEl ? outputEl.textContent : '');
      showToast('Output copied to clipboard', 'success');
    } catch (e) {
      showToast('Copy failed', 'error');
    }
  });
}
// Initialize confidence value on load
if (confSlider && confVal) {
  confVal.textContent = Number(confSlider.value).toFixed(2);
}

// Sample Lime programs (aligned with your grammar)
const samples = {
  overflow: `// Lime sample (illustrative): tight loop without guard can hint at resource issues
fn main() -> int {
    let n: int = 1;
    while (n < 1000000) {
        n = n + 1;
    }
    printf("Done\\n");
    return 0;
}
`,
  fmt: `// Format String vulnerability: user input as format string
fn main() -> int {
    let user_input: str = "admin";
    printf(user_input);
    return 0;
}
`,
  concat: `// Injection-like concatenation pattern (modeled)
fn main() -> int {
    let table: str = "users";
    let name: str = "bob";
    // Building a query-like string (for AI pattern demo)
    printf("%s\\n", table);
    printf(name);
    return 0;
}
`,
  cmd: `// Command-like call representation (pattern demo)
fn main() -> int {
    let cmd: str = "ls -la";
    printf(cmd);
    return 0;
}
`,
  secure: `// Secure: constant format string + parameterization
fn main() -> int {
    let user_input: str = "world";
    printf("%s\\n", user_input);
    return 0;
}
`
};

// Load a default sample
editor.value = samples.fmt;

// Hook up pill buttons
Array.from(document.querySelectorAll('.pill')).forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.getAttribute('data-sample');
    editor.value = samples[key] || '';
    updateEditorStats();
    clearOutputs();
  });
});

function setBanner(state, title, sub) {
  riskBanner.classList.remove('neutral', 'low', 'med', 'high');
  riskBanner.classList.add(state);
  riskBanner.querySelector('.risk-title').textContent = title;
  riskBanner.querySelector('.risk-sub').textContent = sub;
}

function clearOutputs() {
  setBanner('neutral', 'Awaiting Analysis', 'Click "Compile & Analyze" to see results.');
  findingsEl.innerHTML = '';
  errorsEl.textContent = '';
  irEl.textContent = '';
  if (astEl) astEl.textContent = '';
  dlAst.classList.add('disabled');
  dlAst.href = '#';
  dlIr.classList.add('disabled');
  dlIr.href = '#';
  if (outputEl) outputEl.textContent = '';
}

analyzeBtn.addEventListener('click', async () => {
  clearOutputs();
  setBanner('neutral', 'Analyzing...', 'Running lexer, parser, compiler and AI checks...');
  if (analyzeBtn) {
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add('loading');
  }
  if (loadingOverlay) loadingOverlay.classList.add('active');

  const payload = {
    code: editor.value,
    minConfidence: Number(confSlider.value),
    optimize: !!optimizeChk.checked,
    securityLevel: 'strict',
    // If the checkbox is missing (cached HTML), default to true so execution still happens
    run: (runChk ? !!runChk.checked : true)
  };

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    lastResults = data || null;
    renderResults(data);
    showToast('Analysis completed', 'success');
  } catch (e) {
    setBanner('high', 'Request Failed', 'Could not reach the analysis service.');
    errorsEl.textContent = String(e);
    showToast('Request failed', 'error');
  } finally {
    if (analyzeBtn) {
      analyzeBtn.disabled = false;
      analyzeBtn.classList.remove('loading');
    }
    if (loadingOverlay) loadingOverlay.classList.remove('active');
  }
});

function renderResults(data) {
  if (!data || data.ok === false) {
    setBanner('high', 'Analysis Error', data && data.error ? data.error : 'Unknown error');
    return;
  }

  const parseErrs = data.parseErrors || [];
  const compErrs = data.compileErrors || [];
  const allErrs = [];
  if (parseErrs.length) {
    allErrs.push('PARSER ERRORS:');
    parseErrs.forEach(e => allErrs.push('  - ' + e));
  }
  if (compErrs.length) {
    allErrs.push('COMPILER ERRORS:');
    compErrs.forEach(e => allErrs.push('  - ' + e));
  }
  errorsEl.textContent = allErrs.join('\n');

  // AST (pretty print if available)
  if (astEl) {
    try {
      if (data.ast) {
        const astStr = typeof data.ast === 'string' ? data.ast : JSON.stringify(data.ast, null, 2);
        astEl.textContent = astStr.slice(0, 10000);
      } else if (data.artifacts && data.artifacts.astUrl) {
        // Load AST from artifact URL for on-screen accessibility
        fetch(data.artifacts.astUrl + '&_=' + Date.now())
          .then(r => r.text())
          .then(t => { astEl.textContent = t.slice(0, 10000); })
          .catch(() => {});
      } else {
        astEl.textContent = '';
      }
    } catch (_) {
      astEl.textContent = '';
    }
  }

  // IR
  irEl.textContent = (data.ir || '').slice(0, 10000);

  // Security report
  const security = data.security || { summary: {}, findings: [] };
  const findings = security.findings || [];
  const total = findings.length;

  // Execution output
  const exec = data.execution || null;
  if (outputEl) {
    if (exec && exec.ran) {
      const lines = [];
      lines.push(`Return code: ${exec.returnCode}`);
      lines.push(`Duration: ${Number(exec.duration_ms || 0).toFixed(2)} ms`);
      if (exec.stdout) {
        lines.push('--- stdout ---');
        lines.push(exec.stdout);
      }
      if (exec.error) {
        lines.push('--- note ---');
        lines.push(exec.error);
      }
      outputEl.textContent = lines.join('\n');
    } else if (data.blocked) {
      outputEl.textContent = 'Execution blocked due to security findings (strict mode).';
    } else if (data.parseErrors && data.parseErrors.length) {
      outputEl.textContent = 'Not executed due to parse errors.';
    } else {
      outputEl.textContent = 'Not executed.';
    }
  }

  // Enable downloads if artifacts available
  const artifacts = data.artifacts || {};
  if (artifacts.astAvailable && artifacts.astUrl) {
    dlAst.classList.remove('disabled');
    dlAst.href = artifacts.astUrl + '&_=' + Date.now();
  }
  if (artifacts.irAvailable && artifacts.irUrl) {
    dlIr.classList.remove('disabled');
    dlIr.href = artifacts.irUrl + '&_=' + Date.now();
  }
  let sevClass = 'low';
  let title = 'No Vulnerabilities Found';
  let sub = 'Your code appears safe under current rules.';

  const hasCritical = findings.some(f => f.severity === 'CRITICAL');
  const hasHigh = findings.some(f => f.severity === 'HIGH');
  const hasMedium = findings.some(f => f.severity === 'MEDIUM');

  if (hasCritical || hasHigh) {
    sevClass = 'high';
    title = `${total} Vulnerabilit${total === 1 ? 'y' : 'ies'} Found`;
    sub = 'Critical/High issues detected. Compilation would be blocked (strict).';
  } else if (hasMedium) {
    sevClass = 'med';
    title = `${total} Vulnerabilit${total === 1 ? 'y' : 'ies'} Found`;
    sub = 'Medium risk issues detected. Review recommended.';
  } else if (total > 0) {
    sevClass = 'low';
    title = `${total} Low-risk Finding${total === 1 ? '' : 's'}`;
    sub = 'Consider applying suggested mitigations.';
  } else {
    sevClass = 'low';
    title = 'No Vulnerabilities Found';
    sub = 'Security checks passed.';
  }
  setBanner(sevClass, title, sub);

  // Render findings
  findingsEl.innerHTML = findings.map(f => findingCard(f)).join('');
}

function findingCard(f) {
  const sev = (f.severity || 'LOW').toLowerCase();
  return `
    <div class="finding">
      <div class="row">
        <span class="badge ${sev}">${f.severity || 'LOW'}</span>
        <strong>${escapeHtml(f.description || f.type || 'Finding')}</strong>
        <span class="small-note">(Confidence: ${Number(f.confidence ?? 0).toFixed(2)}, CWE: ${escapeHtml(f.cwe_id || '—')})</span>
      </div>
      <div class="location">${escapeHtml(f.location || 'Unknown location')}</div>
      <div class="small-note">${escapeHtml(f.explanation || '')}</div>
      <div class="small-note">Risk: ${escapeHtml(f.risk_impact || '')}</div>
      <div class="small-note">Fix: ${escapeHtml(f.fix_suggestion || '')}</div>
      ${f.code_example ? `<pre class="code-example">${escapeHtml(f.code_example)}</pre>` : ''}
    </div>
  `;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// ========== Extra UI behaviors ==========
// Clear editor
const clearBtn = document.getElementById('clearBtn');
if (clearBtn) {
  clearBtn.addEventListener('click', () => {
    if (!editor) return;
    editor.value = '';
    updateEditorStats();
    clearOutputs();
    showToast('Editor cleared', 'info');
  });
}

// Simple formatter: trim trailing spaces and normalize indentation (basic)
const formatBtn = document.getElementById('formatBtn');
if (formatBtn) {
  formatBtn.addEventListener('click', () => {
    if (!editor) return;
    const formatted = editor.value
      .split('\n')
      .map(line => line.replace(/\s+$/g, ''))
      .join('\n')
      .trim() + '\n';
    editor.value = formatted;
    updateEditorStats();
    showToast('Formatted code', 'success');
  });
}

// Copy AST to clipboard
const copyAstBtn = document.getElementById('copyAst');
if (copyAstBtn) {
  copyAstBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(astEl ? astEl.textContent : '');
      showToast('AST copied to clipboard', 'success');
    } catch (e) {
      showToast('Copy failed', 'error');
    }
  });
}

// Copy IR to clipboard
const copyIrBtn = document.getElementById('copyIr');
if (copyIrBtn) {
  copyIrBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(irEl.textContent || '');
      showToast('IR copied to clipboard', 'success');
    } catch (e) {
      showToast('Copy failed', 'error');
    }
  });
}

// Export findings as JSON
const exportBtn = document.getElementById('exportFindings');
if (exportBtn) {
  exportBtn.addEventListener('click', () => {
    const findings = (lastResults && lastResults.security && lastResults.security.findings) || [];
    const summary = (lastResults && lastResults.security && lastResults.security.summary) || {};
    const exportData = { summary, findings };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_findings_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Findings exported', 'success');
  });
}

// Panel collapse toggles
document.querySelectorAll('.panel .panel-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const panel = btn.closest('.panel');
    if (!panel) return;
    panel.classList.toggle('collapsed');
    const icon = btn.querySelector('.toggle-icon');
    if (icon) icon.textContent = panel.classList.contains('collapsed') ? '►' : '▼';
  });
});
