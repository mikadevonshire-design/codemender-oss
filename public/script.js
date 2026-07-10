/* script.js - Secure Frontend Logic for Gemini Enterprise Employee Database Portal
 *
 * Adheres strictly to mandatory-secure-web-skills:
 * - DOM structural creation via document.createElement() and textContent
 * - No innerHTML or outerHTML assignments
 * - Secure PII presentation and inline Content Policy interception
 */

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initDirectorySearch();
  initContentPolicySandbox();
  initModelArmorInspector();
  fetchAndRenderEmployees('');
});

/* Navigation & Tab Switcher */
function initNavigation() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const views = document.querySelectorAll('.portal-view');

  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabButtons.forEach((b) => b.classList.remove('active'));
      views.forEach((v) => v.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-target');
      const targetView = document.getElementById(targetId);
      if (targetView) {
        targetView.classList.add('active');
      }
    });
  });
}

/* 1. Employee Directory & AI Natural Language Search */
function initDirectorySearch() {
  const searchInput = document.getElementById('employee-search-input');
  const clearBtn = document.getElementById('search-clear-btn');
  const filterButtons = document.querySelectorAll('.filter-pill');

  let activeDept = 'all';

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      fetchAndRenderEmployees(e.target.value, activeDept);
    });
  }

  if (clearBtn && searchInput) {
    clearBtn.addEventListener('click', () => {
      searchInput.value = '';
      fetchAndRenderEmployees('', activeDept);
    });
  }

  filterButtons.forEach((pill) => {
    pill.addEventListener('click', () => {
      filterButtons.forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      activeDept = pill.getAttribute('data-dept');
      fetchAndRenderEmployees(searchInput ? searchInput.value : '', activeDept);
    });
  });
}

async function fetchAndRenderEmployees(query, dept = 'all') {
  const grid = document.getElementById('employee-grid');
  const statsEl = document.getElementById('directory-stats');
  if (!grid) return;

  try {
    const response = await fetch(`/api/employees?q=${encodeURIComponent(query)}`);
    const data = await response.json();
    let employees = data.employees || [];

    if (dept && dept !== 'all') {
      employees = employees.filter((e) => e.department === dept);
    }

    grid.replaceChildren();

    if (statsEl) {
      statsEl.textContent = `Showing ${employees.length} secure employee record(s) in manufacturing-demo-486618`;
    }

    if (employees.length === 0) {
      const emptyMsg = document.createElement('div');
      emptyMsg.textContent = 'No matching employee records found in Gemini Enterprise database.';
      grid.appendChild(emptyMsg);
      return;
    }

    employees.forEach((emp) => {
      const card = createEmployeeCard(emp);
      grid.appendChild(card);
    });
  } catch (error) {
    console.error('Error fetching employee records');
  }
}

function createEmployeeCard(emp) {
  const card = document.createElement('article');
  card.className = 'employee-card';

  const header = document.createElement('div');
  header.className = 'card-header';

  const nameBox = document.createElement('div');
  const nameEl = document.createElement('h3');
  nameEl.className = 'card-name';
  nameEl.textContent = emp.name;

  const roleEl = document.createElement('div');
  roleEl.className = 'card-role';
  roleEl.textContent = emp.role;

  nameBox.appendChild(nameEl);
  nameBox.appendChild(roleEl);

  const badge = document.createElement('span');
  badge.className = emp.status === 'Active' ? 'card-badge' : 'card-badge leave';
  badge.textContent = emp.status;

  header.appendChild(nameBox);
  header.appendChild(badge);

  const details = document.createElement('div');
  details.className = 'card-details';

  details.appendChild(createDetailRow('Department', emp.department));
  details.appendChild(createDetailRow('Location', emp.location));
  details.appendChild(createDetailRow('Clearance', emp.clearance));
  details.appendChild(createDetailRow('Email', emp.email));

  const piiRow = document.createElement('div');
  piiRow.className = 'detail-row';

  const piiLabel = document.createElement('span');
  piiLabel.className = 'detail-label';
  piiLabel.textContent = 'Masked SSN / ID';

  const piiVal = document.createElement('span');
  piiVal.className = 'masked-pii';
  piiVal.textContent = emp.ssnMasked;

  piiRow.appendChild(piiLabel);
  piiRow.appendChild(piiVal);
  details.appendChild(piiRow);

  card.appendChild(header);
  card.appendChild(details);
  return card;
}

function createDetailRow(label, value) {
  const row = document.createElement('div');
  row.className = 'detail-row';

  const labelEl = document.createElement('span');
  labelEl.className = 'detail-label';
  labelEl.textContent = label;

  const valueEl = document.createElement('span');
  valueEl.className = 'detail-value';
  valueEl.textContent = value;

  row.appendChild(labelEl);
  row.appendChild(valueEl);
  return row;
}

/* 2. Content Policy & User Flow Sandbox (File Upload Blocking Verification) */
function initContentPolicySandbox() {
  const form = document.getElementById('ge-query-form');
  const filePicker = document.getElementById('ge-file-picker');
  const selectedBanner = document.getElementById('selected-file-banner');
  const filenameLabel = document.getElementById('attached-filename-label');
  const removeBtn = document.getElementById('remove-file-btn');
  const promptInput = document.getElementById('ge-prompt-input');

  let selectedFile = null;

  if (filePicker) {
    filePicker.addEventListener('change', () => {
      if (filePicker.files && filePicker.files.length > 0) {
        selectedFile = filePicker.files[0];
        if (filenameLabel) {
          filenameLabel.textContent = `Attached: ${selectedFile.name} (${Math.round(selectedFile.size / 1024)} KB)`;
        }
        if (selectedBanner) {
          selectedBanner.style.display = 'flex';
        }
      }
    });
  }

  if (removeBtn) {
    removeBtn.addEventListener('click', () => {
      selectedFile = null;
      if (filePicker) filePicker.value = '';
      if (selectedBanner) selectedBanner.style.display = 'none';
    });
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const promptText = promptInput ? promptInput.value.trim() : '';

      if (!promptText && !selectedFile) return;

      appendChatMessage('user', promptText || `[File Upload Attempt: ${selectedFile.name}]`);
      if (promptInput) promptInput.value = '';

      try {
        const res = await fetch('/api/ge/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            prompt: promptText,
            hasFileUpload: selectedFile !== null,
            filename: selectedFile ? selectedFile.name : ''
          })
        });

        const data = await res.json();

        if (!res.ok || data.blocked) {
          appendChatMessage('blocked', `🛡️ ${data.message}`);
          appendAuditLog('blocked', `BLOCKED (${data.policyName}): ${data.message}`);
        } else {
          appendChatMessage('assistant', `GE Response: ${data.answer}`);
          appendAuditLog('info', `PASSED: Query screened by Model Armor (HIGH confidence) and Content Policy.`);
        }
      } catch (err) {
        appendChatMessage('blocked', 'Network error contacting Gemini Enterprise simulator.');
      }
    });
  }
}

function appendChatMessage(type, text) {
  const container = document.getElementById('chat-messages');
  if (!container) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-msg ${type}`;
  msgDiv.textContent = text;

  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

function appendAuditLog(type, text) {
  const stream = document.getElementById('audit-log-stream');
  if (!stream) return;

  const entry = document.createElement('div');
  entry.className = `audit-entry ${type}`;

  const ts = document.createElement('span');
  ts.className = 'audit-timestamp';
  ts.textContent = new Date().toLocaleTimeString();

  const msg = document.createElement('span');
  msg.className = 'audit-message';
  msg.textContent = text;

  entry.appendChild(ts);
  entry.appendChild(msg);

  stream.appendChild(entry);
  stream.scrollTop = stream.scrollHeight;
}

/* 3. Model Armor High-Confidence Template Inspector */
async function initModelArmorInspector() {
  const refreshBtn = document.getElementById('refresh-config-btn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadAndRenderArmorConfig);
  }
  loadAndRenderArmorConfig();
}

async function loadAndRenderArmorConfig() {
  const filterListEl = document.getElementById('armor-filter-list');
  const jsonViewer = document.getElementById('json-config-viewer');

  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();

    if (jsonViewer) {
      jsonViewer.textContent = JSON.stringify(cfg, null, 2);
    }

    const armorCfg = cfg.modelArmorTemplate || {};
    const filterSettings = armorCfg.filterSettings || {};

    if (filterListEl) {
      filterListEl.replaceChildren();

      Object.entries(filterSettings).forEach(([name, val]) => {
        const row = document.createElement('div');
        row.className = 'filter-row';

        const label = document.createElement('span');
        label.className = 'filter-name';
        label.textContent = formatFilterName(name);

        const badge = document.createElement('span');
        badge.className = 'filter-badge';
        badge.textContent = `ENABLED • ${val.confidenceLevel || 'HIGH'}`;

        row.appendChild(label);
        row.appendChild(badge);
        filterListEl.appendChild(row);
      });
    }
  } catch (error) {
    if (jsonViewer) jsonViewer.textContent = 'Failed to load Model Armor configuration';
  }
}

function formatFilterName(key) {
  return key
    .replace('Settings', '')
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (str) => str.toUpperCase());
}
