const form = document.querySelector("#analyze-form");
const input = document.querySelector("#url-input");
const charCount = document.querySelector("#char-count");
const emptyResult = document.querySelector("#empty-result");
const resultContent = document.querySelector("#result-content");
const resultState = document.querySelector("#result-state");
const category = document.querySelector("#category");
const indicatorCount = document.querySelector("#indicator-count");
const summaryIcon = document.querySelector("#summary-icon");
const scannedUrl = document.querySelector("#scanned-url");
const indicators = document.querySelector("#indicators");
const resultNote = document.querySelector("#result-note");
const formError = document.querySelector("#form-error");
const portalStage = document.querySelector("#portal-stage");
const scanlineSystem = document.querySelector("#red-scanlines");
const scanlineBeamOverlay = document.querySelector("#scanline-beam-overlay");
const historyList = document.querySelector("#history-list");
const historyEmpty = document.querySelector("#history-empty");
const clearHistory = document.querySelector("#clear-history");

const HISTORY_KEY = "cybersentry-history";

function setScanlineState(state) {
  scanlineSystem.classList.remove("is-processing", "is-suspicious", "is-clear", "is-error", "is-complete");
  scanlineBeamOverlay.classList.toggle("is-processing", state === "processing");
  if (state) scanlineSystem.classList.add(`is-${state}`);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[character]));
}

function formatTime(timestamp) {
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(timestamp);
}

function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveHistory(result) {
  const history = [{ ...result, scannedAt: Date.now() }, ...getHistory().filter((item) => item.url !== result.url)].slice(0, 8);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  renderHistory();
}

function renderHistory() {
  const history = getHistory();
  historyEmpty.classList.toggle("is-hidden", history.length > 0);
  clearHistory.disabled = history.length === 0;
  historyList.querySelectorAll(".history-item").forEach((item) => item.remove());
  history.forEach((item) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "history-item";
    row.innerHTML = `
      <span class="history-status ${item.indicator_count ? "review" : "clear"}"></span>
      <span class="history-url">${escapeHtml(item.url)}</span>
      <span class="history-category ${item.indicator_count ? "review-text" : "clear-text"}">${escapeHtml(item.category)}</span>
      <span class="history-time">${formatTime(item.scannedAt)}</span>
      <span class="history-chevron">↗</span>`;
    row.addEventListener("click", () => renderResult(item));
    historyList.appendChild(row);
  });
}

function renderResult(result) {
  portalStage.classList.remove("is-processing");
  portalStage.classList.add("is-complete");
  window.setTimeout(() => portalStage.classList.remove("is-complete"), 800);
  emptyResult.classList.add("is-hidden");
  resultContent.classList.remove("is-hidden");
  const hasIndicators = result.indicator_count > 0;
  setScanlineState(hasIndicators ? "suspicious" : "clear");
  window.setTimeout(() => scanlineSystem.classList.add("is-complete"), 20);
  window.setTimeout(() => scanlineSystem.classList.remove("is-complete"), 900);
  resultState.textContent = hasIndicators ? "Needs review" : "No obvious indicators";
  resultState.className = `result-state ${hasIndicators ? "review-state" : "clear-state"}`;
  category.textContent = result.category;
  category.className = hasIndicators ? "review-heading" : "clear-heading";
  indicatorCount.textContent = `${result.indicator_count} ${result.indicator_count === 1 ? "indicator" : "indicators"}`;
  summaryIcon.textContent = hasIndicators ? "!" : "–";
  summaryIcon.className = `summary-icon ${hasIndicators ? "review-icon" : "clear-icon"}`;
  scannedUrl.textContent = result.url;
  resultNote.textContent = result.note;
  indicators.innerHTML = result.indicators.length
    ? result.indicators.map((item) => `
      <article class="indicator-card ${item.severity}">
        <div class="indicator-symbol">${item.severity === "high" ? "!" : "•"}</div>
        <div class="indicator-body"><div class="indicator-title-row"><h4>${escapeHtml(item.title)}</h4><span>${escapeHtml(item.severity)} attention</span></div><p>${escapeHtml(item.explanation)}</p><code>${escapeHtml(item.evidence)}</code></div>
      </article>`).join("")
    : `<div class="clear-message"><span>✓</span><div><strong>No obvious indicators found</strong><p>This URL did not match the patterns CyberSentry checks for. Stay attentive to the page and request context.</p></div></div>`;
  document.querySelector("#result-panel").scrollIntoView({
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "nearest",
  });
}

input.addEventListener("input", () => {
  charCount.textContent = `${input.value.length.toLocaleString()} / 4,096`;
  formError.textContent = "";
  input.removeAttribute("aria-invalid");
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = form.querySelector("button");
  const url = input.value.trim();
  formError.textContent = "";
  if (!url) {
    input.focus();
    input.setAttribute("aria-invalid", "true");
    formError.textContent = "Enter a URL to analyze.";
    input.classList.add("input-error");
    setTimeout(() => input.classList.remove("input-error"), 500);
    return;
  }
  submit.disabled = true;
  submit.classList.add("loading");
  submit.querySelector("span:nth-child(2)").textContent = "Analyzing locally…";
  portalStage.classList.remove("is-complete");
  portalStage.classList.add("is-processing");
  setScanlineState("processing");
  resultState.textContent = "Local processing";
  resultState.className = "result-state processing-state";
  emptyResult.classList.remove("is-hidden");
  resultContent.classList.add("is-hidden");
  emptyResult.querySelector("h3").textContent = "Inspecting URL text";
  emptyResult.querySelector("p").textContent = "Checking the submitted characters locally. No request is made to the destination.";
  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to analyze this URL.");
    renderResult(result);
    saveHistory(result);
  } catch (error) {
    portalStage.classList.remove("is-processing");
    setScanlineState("error");
    formError.textContent = error.message;
    input.setAttribute("aria-invalid", "true");
    resultState.textContent = "Input needed";
    resultState.className = "result-state input-state";
    emptyResult.classList.remove("is-hidden");
    resultContent.classList.add("is-hidden");
    emptyResult.querySelector("h3").textContent = error.message;
    emptyResult.querySelector("p").textContent = "CyberSentry could not complete this text-only inspection.";
  } finally {
    submit.disabled = false;
    submit.classList.remove("loading");
    submit.querySelector("span:nth-child(2)").textContent = "Analyze URL";
  }
});

clearHistory.addEventListener("click", () => {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

renderHistory();