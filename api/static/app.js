document.addEventListener("DOMContentLoaded", () => {
  // Global States
  let activeTab = "tab-detect";
  let apiOnline = false;

  // View descriptions mapping
  const viewMeta = {
    "tab-detect": {
      title: "Detection Pass",
      desc: "Analyze JSON/XML payloads to extract sensitive PII and PHI entities without modification."
    },
    "tab-mask": {
      title: "Vault Masking",
      desc: "Anonymize fields by replacing identified PII/PHI with reversible tokens, storing encrypted maps in the database."
    },
    "tab-demask": {
      title: "Demask & Restore",
      desc: "Re-hydrate tokenized data back to its original state using a secure document authorization vault ID."
    },
    "tab-registry": {
      title: "Vault Registry",
      desc: "Search, verify, and permanently purge cryptographic token mappings for a given document scope."
    },
    "tab-audit": {
      title: "Audit Trail",
      desc: "Review logs of masking and demasking events. Sensitive details are never written to the audit log."
    }
  };

  // DOM elements cache
  const navItems = document.querySelectorAll(".nav-item");
  const viewPanels = document.querySelectorAll(".view-panel");
  const viewTitleEl = document.getElementById("view-title");
  const viewDescEl = document.getElementById("view-description");
  const apiStatusDot = document.getElementById("api-status-dot");
  const apiStatusText = document.getElementById("api-status-text");

  // Load sample buttons
  const btnLoadJson = document.getElementById("btn-load-json");
  const btnLoadXml = document.getElementById("btn-load-xml");

  // Inputs
  const detectInput = document.getElementById("detect-input");
  const maskInput = document.getElementById("mask-input");
  const maskDocIdInput = document.getElementById("mask-doc-id-input");
  const btnGenerateDocId = document.getElementById("btn-generate-doc-id");
  const demaskInput = document.getElementById("demask-input");
  const demaskDocIdInput = document.getElementById("demask-doc-id-input");
  const registryDocIdInput = document.getElementById("registry-doc-id-input");

  // Detailed Tables DOM cache
  const maskEntitiesCard = document.getElementById("mask-entities-card");
  const maskEntitiesCountBadge = document.getElementById("mask-entities-count-badge");
  const maskEntitiesTableBody = document.getElementById("mask-entities-table-body");

  const demaskEntitiesCard = document.getElementById("demask-entities-card");
  const demaskEntitiesCountBadge = document.getElementById("demask-entities-count-badge");
  const demaskEntitiesTableBody = document.getElementById("demask-entities-table-body");

  // -------------------------------------------------------------
  // Toast Notifications
  // -------------------------------------------------------------
  function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    // Add appropriate icon based on type
    let iconSvg = "";
    if (type === "success") {
      iconSvg = `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" style="width: 18px; height: 18px; color: var(--color-success); flex-shrink: 0;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7" /></svg>`;
    } else if (type === "error") {
      iconSvg = `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" style="width: 18px; height: 18px; color: var(--color-danger); flex-shrink: 0;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>`;
    } else {
      iconSvg = `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" style="width: 18px; height: 18px; color: var(--color-brand); flex-shrink: 0;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`;
    }

    toast.innerHTML = `
      ${iconSvg}
      <span class="toast-message">${escapeHtml(message)}</span>
    `;
    
    container.appendChild(toast);
    
    // Animate out
    setTimeout(() => {
      toast.classList.add("fade-out");
      toast.addEventListener("animationend", () => {
        toast.remove();
      });
    }, 3000);
  }

  // -------------------------------------------------------------
  // API Connection Check
  // -------------------------------------------------------------
  async function checkApiConnection() {
    try {
      const res = await fetch("/health");
      if (res.ok) {
        const data = await res.json();
        if (data.status === "ok") {
          apiOnline = true;
          apiStatusDot.className = "status-indicator online";
          apiStatusText.textContent = "Vault API Connected";
          return;
        }
      }
      throw new Error();
    } catch (e) {
      apiOnline = false;
      apiStatusDot.className = "status-indicator offline";
      apiStatusText.textContent = "Vault API Offline";
    }
  }

  // Poll connection every 10 seconds
  checkApiConnection();
  setInterval(checkApiConnection, 10000);

  // -------------------------------------------------------------
  // Format Auto-Detection
  // -------------------------------------------------------------
  function autoDetectFormat(text) {
    const trimmed = text.trim();
    if (!trimmed) return null;
    return trimmed.startsWith("<") ? "xml" : "json";
  }

  function updateFormatBadge(textareaId, badgeId) {
    const text = document.getElementById(textareaId).value;
    const badge = document.getElementById(badgeId);
    const fmt = autoDetectFormat(text);

    if (fmt === "json") {
      badge.textContent = "JSON Format Detected";
      badge.className = "badge detected-json";
    } else if (fmt === "xml") {
      badge.textContent = "XML Format Detected";
      badge.className = "badge detected-xml";
    } else {
      badge.textContent = "Auto-detecting format";
      badge.className = "badge";
    }
  }

  // Add event listeners for format detection
  detectInput.addEventListener("input", () => updateFormatBadge("detect-input", "detect-format-badge"));
  maskInput.addEventListener("input", () => updateFormatBadge("mask-input", "mask-format-badge"));
  demaskInput.addEventListener("input", () => updateFormatBadge("demask-input", "demask-format-badge"));

  // -------------------------------------------------------------
  // Sample Data Loading
  // -------------------------------------------------------------
  const FALLBACK_SAMPLES = {
    json: `{
  "patient": {
    "patient_name": "Asha Verma",
    "dob": "1989-04-12",
    "ssn": "123-45-6789",
    "email": "asha.verma@example.com",
    "phone": "9876543210",
    "mrn": "MRN-0234891",
    "address": "221B Brigade Road, Bengaluru, 560001"
  },
  "encounter": {
    "diagnosis": "E11.9",
    "notes": "Patient presents with elevated glucose, contact at asha.verma@example.com for follow-up.",
    "prescription": "Metformin 500mg BID"
  },
  "insurance": {
    "primary": {
      "insurance_id": "INS123456789",
      "policy_number": "POL98765432"
    },
    "secondary": {
      "insurance_id": "SEC55667788"
    }
  }
}`,
    xml: `<Patient>
  <Name>Rohan Mehta</Name>
  <DOB>1991-07-22</DOB>
  <SSN>987-65-4321</SSN>
  <Email>rohan.mehta@example.com</Email>
  <MRN>MRN-0098123</MRN>
  <Encounter>
    <Diagnosis icd_code="J45.909">Asthma, unspecified</Diagnosis>
    <Notes>Reachable at rohan.mehta@example.com or 9123456780 if labs change.</Notes>
    <Prescription>Albuterol inhaler PRN</Prescription>
  </Encounter>
  <Insurance insurance_id="INS998877665">
    <PolicyNumber>POL11223344</PolicyNumber>
  </Insurance>
</Patient>`
  };

  async function loadSample(format) {
    let content = "";
    try {
      const res = await fetch(`/api/samples/${format}`);
      if (!res.ok) throw new Error("Failed to load sample");
      const data = await res.json();
      content = data.content;
    } catch (e) {
      // Fallback if API is offline or page is opened via file:// protocol
      content = FALLBACK_SAMPLES[format];
    }
    
    // Determine which textarea to load into
    if (activeTab === "tab-detect") {
      detectInput.value = content;
      updateFormatBadge("detect-input", "detect-format-badge");
    } else if (activeTab === "tab-mask") {
      maskInput.value = content;
      updateFormatBadge("mask-input", "mask-format-badge");
    } else if (activeTab === "tab-demask") {
      demaskInput.value = content;
      updateFormatBadge("demask-input", "demask-format-badge");
    } else {
      showToast("Samples can only be loaded in scanner, masking or demasking views.", "info");
      return;
    }
    showToast(`Fictional sample ${format.toUpperCase()} payload loaded successfully!`, "success");
  }

  btnLoadJson.addEventListener("click", () => loadSample("json"));
  btnLoadXml.addEventListener("click", () => loadSample("xml"));

  // -------------------------------------------------------------
  // File Upload Handling (PDF, JSON, XML, TXT)
  // -------------------------------------------------------------
  const fileUploadInput = document.getElementById("file-upload-input");

  async function processUploadedFile(file) {
    if (!file) return;

    const extension = file.name.split('.').pop().toLowerCase();
    const activeTextarea = getActiveInputTextarea();
    if (!activeTextarea) {
      showToast("Cannot upload a file in the current view.", "error");
      return;
    }

    if (extension === "pdf") {
      showToast(`Uploading and extracting text from ${file.name}...`, "info");
      const formData = new FormData();
      formData.append("file", file);

      try {
        const res = await fetch("/api/extract-pdf", {
          method: "POST",
          body: formData
        });

        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "PDF extraction failed");
        }

        const data = await res.json();
        activeTextarea.value = data.content;
        updateActiveFormatBadge();
        showToast("PDF text extracted successfully!", "success");
      } catch (e) {
        showToast(e.message, "error");
      }
    } else if (["json", "xml", "txt"].includes(extension)) {
      showToast(`Loading local file ${file.name}...`, "info");
      const reader = new FileReader();
      reader.onload = (e) => {
        activeTextarea.value = e.target.result;
        updateActiveFormatBadge();
        showToast(`${file.name} loaded successfully!`, "success");
      };
      reader.onerror = () => {
        showToast(`Failed to read file ${file.name}`, "error");
      };
      reader.readAsText(file);
    } else {
      showToast("Unsupported file type. Please upload a PDF, JSON, XML, or TXT file.", "error");
    }
  }

  if (fileUploadInput) {
    fileUploadInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) {
        processUploadedFile(file);
        // Clear input value so selecting the same file again triggers change event
        fileUploadInput.value = "";
      }
    });
  }

  function getActiveInputTextarea() {
    if (activeTab === "tab-detect") return detectInput;
    if (activeTab === "tab-mask") return maskInput;
    if (activeTab === "tab-demask") return demaskInput;
    return null;
  }

  function updateActiveFormatBadge() {
    if (activeTab === "tab-detect") updateFormatBadge("detect-input", "detect-format-badge");
    else if (activeTab === "tab-mask") updateFormatBadge("mask-input", "mask-format-badge");
    else if (activeTab === "tab-demask") updateFormatBadge("demask-input", "demask-format-badge");
  }

  // -------------------------------------------------------------
  // Drag & Drop Handling
  // -------------------------------------------------------------
  const textareasToDrop = [detectInput, maskInput, demaskInput];

  textareasToDrop.forEach(textarea => {
    if (!textarea) return;

    textarea.addEventListener("dragover", (e) => {
      e.preventDefault();
      textarea.classList.add("drag-over");
    });

    textarea.addEventListener("dragleave", () => {
      textarea.classList.remove("drag-over");
    });

    textarea.addEventListener("drop", (e) => {
      e.preventDefault();
      textarea.classList.remove("drag-over");
      
      const file = e.dataTransfer.files[0];
      if (file) {
        processUploadedFile(file);
      }
    });
  });

  // -------------------------------------------------------------
  // View Switcher (Tabs)
  // -------------------------------------------------------------
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");
      
      // Toggle sidebar active item
      navItems.forEach(n => n.classList.remove("active"));
      item.classList.add("active");
      
      // Toggle panel visibility
      viewPanels.forEach(p => p.classList.remove("active"));
      document.getElementById(targetTab).classList.add("active");
      
      // Update header details
      activeTab = targetTab;
      viewTitleEl.textContent = viewMeta[targetTab].title;
      viewDescEl.textContent = viewMeta[targetTab].desc;

      // Handle loading headers / buttons
      const lblFileUpload = document.getElementById("lbl-file-upload");
      if (targetTab === "tab-detect" || targetTab === "tab-mask" || targetTab === "tab-demask") {
        btnLoadJson.classList.remove("hidden");
        btnLoadXml.classList.remove("hidden");
        if (lblFileUpload) lblFileUpload.classList.remove("hidden");
      } else {
        btnLoadJson.classList.add("hidden");
        btnLoadXml.classList.add("hidden");
        if (lblFileUpload) lblFileUpload.classList.add("hidden");
      }

      // Special action: Load audit logs on navigation to Audit panel
      if (targetTab === "tab-audit") {
        loadAuditLogs();
      }
    });
  });

  // -------------------------------------------------------------
  // Clipboard Copy Actions
  // -------------------------------------------------------------
  document.addEventListener("click", async (e) => {
    // Find closest copy button
    const btn = e.target.closest(".btn-copy");
    if (!btn) return;
    
    const targetId = btn.getAttribute("data-copy-target");
    const targetEl = document.getElementById(targetId);
    if (!targetEl) return;
    
    let text = "";
    if (targetEl.tagName === "TEXTAREA" || targetEl.tagName === "INPUT") {
      text = targetEl.value;
    } else {
      text = targetEl.innerText || targetEl.textContent;
    }

    if (!text.trim()) {
      showToast("No content to copy!", "error");
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      showToast("Copied to clipboard!", "success");
    } catch (err) {
      showToast("Failed to copy automatically.", "error");
    }
  });

  // -------------------------------------------------------------
  // VIEW 1: DETECT PASS
  // -------------------------------------------------------------
  const btnRunDetect = document.getElementById("btn-run-detect");
  const detectSpinner = document.getElementById("detect-spinner");
  const detectResultsContainer = document.getElementById("detect-results-container");
  const detectCountBadge = document.getElementById("detect-count-badge");

  btnRunDetect.addEventListener("click", async () => {
    const rawContent = detectInput.value.trim();
    if (!rawContent) {
      showToast("Please enter a JSON or XML payload to analyze.", "error");
      return;
    }

    // Set UI loading state
    btnRunDetect.disabled = true;
    detectSpinner.classList.remove("hidden");
    detectCountBadge.textContent = "Scanning...";

    try {
      const res = await fetch("/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: rawContent })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "API response failed");
      }

      const data = await res.json();
      renderDetectResults(data.entities);
    } catch (e) {
      showToast(e.message, "error");
      detectCountBadge.textContent = "Error";
      detectResultsContainer.innerHTML = `
        <div class="empty-state">
          <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" style="color: var(--color-danger);">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <h4>Analysis Failed</h4>
          <p>${escapeHtml(e.message)}</p>
        </div>
      `;
    } finally {
      btnRunDetect.disabled = false;
      detectSpinner.classList.add("hidden");
    }
  });

  function renderDetectResults(entities) {
    detectResultsContainer.innerHTML = "";
    detectCountBadge.textContent = `${entities.length} items`;

    if (entities.length === 0) {
      detectResultsContainer.innerHTML = `
        <div class="empty-state">
          <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" style="color: var(--color-success);">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
          <h4>No PII or PHI Detected</h4>
          <p>The payload is clean of identifiable headers matching the configured regexes and keys.</p>
        </div>
      `;
      showToast("Scan finished: no sensitive variables found.", "success");
      return;
    }

    entities.forEach(entity => {
      const card = document.createElement("div");
      const categoryClass = entity.category.toLowerCase() === "pii" ? "pii-class" : "phi-class";
      card.className = `entity-card ${categoryClass}`;
      
      card.innerHTML = `
        <div class="entity-card-header">
          <span class="entity-type-badge">${escapeHtml(entity.entity_type)}</span>
          <span class="entity-category-badge">${escapeHtml(entity.category)}</span>
        </div>
        <div class="entity-path">${escapeHtml(entity.field_path)}</div>
        <div class="entity-value">${escapeHtml(entity.value)}</div>
      `;
      
      detectResultsContainer.appendChild(card);
    });

    showToast(`Scan complete: found ${entities.length} entities.`, "info");
  }

  // -------------------------------------------------------------
  // VIEW 2: VAULT MASKING
  // -------------------------------------------------------------
  const btnRunMask = document.getElementById("btn-run-mask");
  const maskSpinner = document.getElementById("mask-spinner");
  const maskOutput = document.getElementById("mask-output");
  const btnCopyMasked = document.getElementById("btn-copy-masked");
  
  // Banner fields
  const maskMetaBanner = document.getElementById("mask-meta-banner");
  const maskedDocIdValue = document.getElementById("masked-doc-id-value");
  const maskStatPii = document.getElementById("mask-stat-pii");
  const maskStatPhi = document.getElementById("mask-stat-phi");
  const maskStatTotal = document.getElementById("mask-stat-total");

  // Helper to generate a UUID for Document ID
  function generateUUID() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      const r = (Math.random() * 16) | 0;
      const v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  if (btnGenerateDocId) {
    btnGenerateDocId.addEventListener("click", () => {
      maskDocIdInput.value = generateUUID();
      showToast("Generated a new random Document ID!", "success");
    });
  }

  btnRunMask.addEventListener("click", async () => {
    const rawContent = maskInput.value.trim();
    if (!rawContent) {
      showToast("Please enter a JSON or XML payload to mask.", "error");
      return;
    }

    btnRunMask.disabled = true;
    maskSpinner.classList.remove("hidden");
    maskMetaBanner.classList.add("hidden");
    maskEntitiesCard.classList.add("hidden");
    maskOutput.value = "";
    btnCopyMasked.classList.add("hidden");

    const reqPayload = { content: rawContent };
    const customDocId = maskDocIdInput.value.trim();
    if (customDocId) {
      reqPayload.document_id = customDocId;
    }

    try {
      const res = await fetch("/mask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqPayload)
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Masking failed");
      }

      const data = await res.json();
      
      // Render output
      maskOutput.value = data.masked_content;
      btnCopyMasked.classList.remove("hidden");

      // Render stats details
      maskedDocIdValue.textContent = data.document_id;
      maskStatPii.textContent = data.summary.PII;
      maskStatPhi.textContent = data.summary.PHI;
      maskStatTotal.textContent = data.summary.tokens.length;
      maskMetaBanner.classList.remove("hidden");

      // Render detailed masked entities table
      renderMaskedEntities(data.summary.masked_entities);

      // Auto load document ID to Demasking input box for developer convenience!
      demaskDocIdInput.value = data.document_id;
      registryDocIdInput.value = data.document_id;

      showToast("Document masked successfully! Tokens generated.", "success");
    } catch (e) {
      showToast(e.message, "error");
      maskOutput.value = `Error: ${e.message}`;
    } finally {
      btnRunMask.disabled = false;
      maskSpinner.classList.add("hidden");
    }
  });

  function renderMaskedEntities(entities) {
    maskEntitiesTableBody.innerHTML = "";
    if (!entities || entities.length === 0) {
      maskEntitiesCard.classList.add("hidden");
      return;
    }

    maskEntitiesCountBadge.textContent = `${entities.length} items`;
    entities.forEach(entity => {
      const tr = document.createElement("tr");
      const catBadgeClass = entity.category.toLowerCase() === "pii" ? "pii-class" : "phi-class";
      tr.innerHTML = `
        <td><code style="font-family: var(--font-mono); font-size: 0.8rem; background-color: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px;">${escapeHtml(entity.token)}</code></td>
        <td><span style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(entity.entity_type)}</span></td>
        <td><span class="badge ${catBadgeClass}" style="text-transform: uppercase; font-size: 0.65rem; font-weight: 700; border-radius: 99px; padding: 1px 6px;">${escapeHtml(entity.category)}</span></td>
        <td><code style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary);">${escapeHtml(entity.field_path)}</code></td>
        <td><code style="font-family: var(--font-mono); font-size: 0.8rem; background-color: rgba(0,0,0,0.15); padding: 2px 6px; border-radius: 4px; color: #fff;">${escapeHtml(entity.raw_value)}</code></td>
      `;
      maskEntitiesTableBody.appendChild(tr);
    });
    maskEntitiesCard.classList.remove("hidden");
  }

  // -------------------------------------------------------------
  // VIEW 3: DEMASK & RESTORE
  // -------------------------------------------------------------
  const btnRunDemask = document.getElementById("btn-run-demask");
  const demaskSpinner = document.getElementById("demask-spinner");
  const demaskOutput = document.getElementById("demask-output");
  const btnCopyRestored = document.getElementById("btn-copy-restored");

  // Banner details
  const demaskMetaBanner = document.getElementById("demask-meta-banner");
  const demaskStatRestored = document.getElementById("demask-stat-restored");
  const demaskStatUnresolved = document.getElementById("demask-stat-unresolved");
  const demaskUnresolvedCard = document.getElementById("demask-unresolved-card");

  btnRunDemask.addEventListener("click", async () => {
    const docId = demaskDocIdInput.value.trim();
    const maskedText = demaskInput.value.trim();

    if (!docId) {
      showToast("Please provide the unique Document ID associated with the token mappings.", "error");
      return;
    }
    if (!maskedText) {
      showToast("Please paste the tokenized JSON/XML content.", "error");
      return;
    }

    btnRunDemask.disabled = true;
    demaskSpinner.classList.remove("hidden");
    demaskMetaBanner.classList.add("hidden");
    demaskEntitiesCard.classList.add("hidden");
    demaskOutput.value = "";
    btnCopyRestored.classList.add("hidden");

    try {
      const res = await fetch("/demask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: maskedText,
          document_id: docId
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Demasking lookup failed");
      }

      const data = await res.json();
      
      // Update values
      demaskOutput.value = data.original_content;
      btnCopyRestored.classList.remove("hidden");

      // Stats
      demaskStatRestored.textContent = data.summary.restored;
      const unresolvedCount = data.summary.unresolved.length;
      demaskStatUnresolved.textContent = unresolvedCount;

      if (unresolvedCount > 0) {
        demaskUnresolvedCard.className = "stat-card red-glow";
        showToast(`Demasked with ${unresolvedCount} unresolved tokens. Check document ID!`, "error");
      } else {
        demaskUnresolvedCard.className = "stat-card";
        showToast("Demasking complete: all tokens resolved!", "success");
      }
      
      // Render detailed restored entities table
      renderDemaskedEntities(data.summary.restored_entities);

      demaskMetaBanner.classList.remove("hidden");
    } catch (e) {
      showToast(e.message, "error");
      demaskOutput.value = `Error: ${e.message}`;
    } finally {
      btnRunDemask.disabled = false;
      demaskSpinner.classList.add("hidden");
    }
  });

  function renderDemaskedEntities(entities) {
    demaskEntitiesTableBody.innerHTML = "";
    if (!entities || entities.length === 0) {
      demaskEntitiesCard.classList.add("hidden");
      return;
    }

    demaskEntitiesCountBadge.textContent = `${entities.length} items`;
    entities.forEach(entity => {
      const tr = document.createElement("tr");
      const catBadgeClass = entity.category.toLowerCase() === "pii" ? "pii-class" : "phi-class";
      tr.innerHTML = `
        <td><code style="font-family: var(--font-mono); font-size: 0.8rem; background-color: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px;">${escapeHtml(entity.token)}</code></td>
        <td><span style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(entity.entity_type)}</span></td>
        <td><span class="badge ${catBadgeClass}" style="text-transform: uppercase; font-size: 0.65rem; font-weight: 700; border-radius: 99px; padding: 1px 6px;">${escapeHtml(entity.category)}</span></td>
        <td><code style="font-family: var(--font-mono); font-size: 0.8rem; background-color: rgba(0,0,0,0.15); padding: 2px 6px; border-radius: 4px; color: #fff;">${escapeHtml(entity.real_value)}</code></td>
      `;
      demaskEntitiesTableBody.appendChild(tr);
    });
    demaskEntitiesCard.classList.remove("hidden");
  }

  // -------------------------------------------------------------
  // VIEW 4: VAULT REGISTRY
  // -------------------------------------------------------------
  const btnRegistrySearch = document.getElementById("btn-registry-search");
  const registryResultsWrapper = document.getElementById("registry-results-wrapper");
  const registryEmptyState = document.getElementById("registry-empty-state");
  const registryDocIdDisplay = document.getElementById("registry-doc-id-display");
  const registryTableBody = document.getElementById("registry-table-body");
  
  // Purge trigger
  const btnTriggerPurge = document.getElementById("btn-trigger-purge");
  const modalPurge = document.getElementById("modal-purge");
  const modalPurgeDocId = document.getElementById("modal-purge-doc-id");
  const modalPurgeConfirmInput = document.getElementById("modal-purge-confirm-input");
  const btnConfirmPurge = document.getElementById("btn-confirm-purge");
  const btnCancelPurge = document.getElementById("btn-cancel-purge");
  const btnCloseModalX = document.getElementById("btn-close-modal-x");

  // Keep track of active registry query doc ID
  let activeRegistryDocId = "";

  btnRegistrySearch.addEventListener("click", () => performVaultLookup());
  registryDocIdInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") performVaultLookup();
  });

  async function performVaultLookup() {
    const docId = registryDocIdInput.value.trim();
    if (!docId) {
      showToast("Please enter a document_id to search.", "error");
      return;
    }

    try {
      const res = await fetch(`/vault/${docId}`);
      if (!res.ok) throw new Error("Vault query failed");
      const data = await res.json();
      
      activeRegistryDocId = docId;
      renderRegistry(data.entries);
    } catch (e) {
      showToast(`Error looking up document: ${e.message}`, "error");
    }
  }

  function renderRegistry(entries) {
    registryTableBody.innerHTML = "";
    registryDocIdDisplay.textContent = activeRegistryDocId;
    
    registryEmptyState.classList.add("hidden");
    registryResultsWrapper.classList.remove("hidden");

    if (entries.length === 0) {
      registryTableBody.innerHTML = `
        <tr>
          <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 32px 0;">
            No token records registered for this Document ID.
          </td>
        </tr>
      `;
      return;
    }

    entries.forEach(entry => {
      const tr = document.createElement("tr");
      
      const catClass = entry.category.toLowerCase() === "pii" ? "pii" : "phi";
      
      tr.innerHTML = `
        <td><code class="token-code">${escapeHtml(entry.token)}</code></td>
        <td><strong>${escapeHtml(entry.entity_type)}</strong></td>
        <td><span class="category-lbl ${catClass}">${escapeHtml(entry.category)}</span></td>
        <td><code style="word-break: break-all;">${escapeHtml(entry.field_path || "N/A")}</code></td>
      `;
      
      registryTableBody.appendChild(tr);
    });
  }

  // Modal handlers
  btnTriggerPurge.addEventListener("click", () => {
    if (!activeRegistryDocId) return;
    modalPurgeDocId.textContent = activeRegistryDocId;
    modalPurgeConfirmInput.value = "";
    
    btnConfirmPurge.disabled = true;
    btnConfirmPurge.classList.add("disabled");
    
    modalPurge.classList.remove("hidden");
  });

  // Enable confirm button only if user types PURGE
  modalPurgeConfirmInput.addEventListener("input", () => {
    const inputVal = modalPurgeConfirmInput.value.trim();
    if (inputVal === "PURGE") {
      btnConfirmPurge.disabled = false;
      btnConfirmPurge.classList.remove("disabled");
    } else {
      btnConfirmPurge.disabled = true;
      btnConfirmPurge.classList.add("disabled");
    }
  });

  function closeModal() {
    modalPurge.classList.add("hidden");
  }

  btnCancelPurge.addEventListener("click", closeModal);
  btnCloseModalX.addEventListener("click", closeModal);
  
  btnConfirmPurge.addEventListener("click", async () => {
    if (btnConfirmPurge.disabled || !activeRegistryDocId) return;

    try {
      const res = await fetch(`/vault/${activeRegistryDocId}`, {
        method: "DELETE"
      });

      if (!res.ok) throw new Error("Purge request failed");
      
      showToast(`Cryptographic vault for ${activeRegistryDocId} purged.`, "success");
      closeModal();
      
      // Reset view
      registryResultsWrapper.classList.add("hidden");
      registryEmptyState.classList.remove("hidden");
      registryDocIdInput.value = "";
      activeRegistryDocId = "";
    } catch (e) {
      showToast(`Failed to purge document: ${e.message}`, "error");
    }
  });



  // -------------------------------------------------------------
  // VIEW 5: AUDIT LOGS
  // -------------------------------------------------------------
  const btnRefreshAudit = document.getElementById("btn-refresh-audit");
  const auditTableBody = document.getElementById("audit-table-body");

  btnRefreshAudit.addEventListener("click", () => loadAuditLogs());

  async function loadAuditLogs() {
    auditTableBody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 24px 0;">
          Fetching logs...
        </td>
      </tr>
    `;

    try {
      const res = await fetch("/api/audit");
      if (!res.ok) throw new Error("Audit fetch failed");
      const logs = await res.json();
      
      renderAuditLogs(logs);
    } catch (e) {
      showToast(`Could not fetch audit trail: ${e.message}`, "error");
      auditTableBody.innerHTML = `
        <tr>
          <td colspan="4" style="text-align: center; color: var(--color-danger); padding: 24px 0;">
            Failed to load audit trail.
          </td>
        </tr>
      `;
    }
  }

  function renderAuditLogs(logs) {
    auditTableBody.innerHTML = "";
    
    if (logs.length === 0) {
      auditTableBody.innerHTML = `
        <tr>
          <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 32px 0;">
            Audit trail is currently empty. Execute a mask or demask operation to populate.
          </td>
        </tr>
      `;
      return;
    }

    logs.forEach(log => {
      const tr = document.createElement("tr");
      
      // Format timestamp
      let formattedTime = log.timestamp;
      try {
        const date = new Date(log.timestamp);
        formattedTime = date.toISOString().replace("T", " ").substring(0, 19);
      } catch (err) {}

      // Action styling
      const act = log.action.toUpperCase();
      let badgeClass = "action-mask";
      if (act === "DEMASK") badgeClass = "action-demask";
      if (act === "PURGE" || act === "DELETE") badgeClass = "action-purge";

      // Details parsing
      let detailsText = "";
      if (log.details) {
        if (log.details.PII !== undefined) {
          detailsText = `Masked ${log.details.PII} PII, ${log.details.PHI} PHI`;
        } else if (log.details.restored !== undefined) {
          detailsText = `Restored ${log.details.restored} tokens. Unresolved: ${log.details.unresolved ? log.details.unresolved.length : 0}`;
        } else if (log.details.purged) {
          detailsText = `Permanently purged security keys from vault.`;
        } else {
          detailsText = JSON.stringify(log.details);
        }
      }

      tr.innerHTML = `
        <td style="color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(formattedTime)}</td>
        <td><span class="audit-action-badge ${badgeClass}">${escapeHtml(act)}</span></td>
        <td><code style="font-size: 0.8rem;">${escapeHtml(log.document_id)}</code></td>
        <td style="color: var(--text-primary); font-weight: 500;">${escapeHtml(detailsText)}</td>
      `;
      
      auditTableBody.appendChild(tr);
    });
  }

  // -------------------------------------------------------------
  // HTML Escaping Utility
  // -------------------------------------------------------------
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
