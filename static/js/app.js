const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const button = document.querySelector("#analyze-button");
const errorMessage = document.querySelector("#form-error");

function textElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function renderResult(result) {
  document.querySelector("#result-section").hidden = false;
  document.querySelector("#risk-score").textContent = String(result.risk_score);
  const scoreRing = document.querySelector("#score-ring");
  scoreRing.className = `score-ring ${result.category.toLowerCase()}`;
  document.querySelector("#score-progress").setAttribute(
    "stroke-dashoffset",
    String(327 * (1 - result.risk_score / 100)),
  );
  const badge = document.querySelector("#risk-category");
  badge.textContent = `${result.category} risk`;
  badge.className = `risk-badge ${result.category.toLowerCase()}`;
  document.querySelector("#result-url").textContent = result.url;
  document.querySelector("#result-mode").textContent = result.model_available
    ? `Model + heuristics · model ${result.model_score}/100 · rules ${result.heuristic_score}/100`
    : `Heuristic-only · rules ${result.heuristic_score}/100`;
  document.querySelector("#score-breakdown").textContent = result.model_available
    ? "Overall score blends model estimate (70%) and rules (30%)"
    : "Overall score uses heuristic rules only";
  document.querySelector("#result-disclaimer").textContent = result.disclaimer;

  const list = document.querySelector("#reason-list");
  list.replaceChildren();
  for (const reason of result.reasons) {
    const item = document.createElement("li");
    item.append(textElement("span", `reason-dot ${reason.severity}`, ""));
    item.append(textElement("span", "", reason.message));
    list.append(item);
  }
}

function renderHistory(data) {
  for (const key of ["total", "high", "medium", "low"]) {
    document.querySelector(`#stat-${key}`).textContent = String(data.statistics[key]);
  }
  const list = document.querySelector("#history-list");
  list.replaceChildren();
  if (data.scans.length === 0) {
    list.append(textElement("div", "history-empty", "Your recent scans will appear here."));
    return;
  }
  for (const scan of data.scans) {
    const row = document.createElement("div");
    row.className = "history-row";
    row.append(textElement("span", "history-url", scan.url));
    const score = document.createElement("span");
    score.className = "history-score";
    score.textContent = `${scan.risk_score}/100`;
    const category = textElement("span", `history-category ${scan.category.toLowerCase()}`, scan.category);
    score.append(category);
    row.append(score);
    const date = new Date(scan.scanned_at);
    row.append(textElement("span", "history-date", Number.isNaN(date.getTime()) ? scan.scanned_at : date.toLocaleString()));
    list.append(row);
  }
}

async function loadHistory() {
  const response = await fetch("/api/history");
  if (!response.ok) throw new Error("Could not load scan history.");
  renderHistory(await response.json());
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  button.disabled = true;
  button.firstElementChild.textContent = "Analyzing…";
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input.value }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to analyze this URL.");
    renderResult(result);
    await loadHistory();
    document.querySelector("#result-section").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    errorMessage.textContent = error.message || "The scan could not be completed.";
    errorMessage.hidden = false;
  } finally {
    button.disabled = false;
    button.firstElementChild.textContent = "Analyze URL";
  }
});

document.querySelector("#clear-history").addEventListener("click", async () => {
  if (!window.confirm("Clear all saved scan history? This cannot be undone.")) return;
  try {
    const response = await fetch("/api/history", { method: "DELETE" });
    if (!response.ok) throw new Error("Could not clear scan history.");
    await loadHistory();
  } catch (error) {
    window.alert(error.message || "Could not clear scan history.");
  }
});

loadHistory().catch((error) => {
  document.querySelector("#history-list").replaceChildren(
    textElement("div", "history-empty", error.message || "Could not load scan history."),
  );
});
