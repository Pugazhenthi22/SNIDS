const POLL_INTERVAL_MS = 2000;

const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const clockEl = document.getElementById("clock");

let timelineChart = null;
let severityChart = null;
let lastAlertCount = 0;

function tickClock() {
  clockEl.textContent = new Date().toLocaleTimeString();
}
tickClock();
setInterval(tickClock, 1000);

async function fetchAlerts() {
  try {
    const res = await fetch("/api/alerts");
    if (!res.ok) throw new Error("Bad response");
    const data = await res.json();

    statusDot.classList.add("live");
    statusText.textContent = "Live";

    render(data);
  } catch (err) {
    statusDot.classList.remove("live");
    statusText.textContent = "Disconnected";
  }
}

function render(data) {
  document.getElementById("totalFlows").textContent = data.total;
  document.getElementById("benignCount").textContent = data.benign;
  document.getElementById("attackCount").textContent = data.attacks;
  document.getElementById("attackRate").textContent = `${data.attack_rate}%`;
  document.getElementById("highSeverity").textContent =
    data.severity_counts.HIGH || 0;

  renderTimelineChart(data.timeline || []);
  renderSeverityChart(data.severity_counts || { LOW: 0, HIGH: 0 });
  renderTopSources(data.top_sources || []);
  renderAlertsTable(data.recent_alerts || []);
}

function renderTimelineChart(timeline) {
  // "YYYY-MM-DDTHH:MM" -> "MM-DD HH:MM", so multi-day data never looks ambiguous
  const labels = timeline.map((t) => t.time.slice(5).replace("T", " "));
  const benignData = timeline.map((t) => t.benign);
  const attackData = timeline.map((t) => t.attack);

  if (!timelineChart) {
    const ctx = document.getElementById("timelineChart").getContext("2d");
    timelineChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Benign",
            data: benignData,
            borderColor: "#059669",
            backgroundColor: "rgba(5,150,105,0.10)",
            fill: true,
            tension: 0.35,
            pointRadius: 0,
          },
          {
            label: "Attack",
            data: attackData,
            borderColor: "#dc2626",
            backgroundColor: "rgba(220,38,38,0.10)",
            fill: true,
            tension: 0.35,
            pointRadius: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: "#334155", boxWidth: 12 } },
        },
        scales: {
          x: { ticks: { color: "#64748b" }, grid: { color: "#e2e8f0" } },
          y: { ticks: { color: "#64748b" }, grid: { color: "#e2e8f0" }, beginAtZero: true },
        },
      },
    });
  } else {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = benignData;
    timelineChart.data.datasets[1].data = attackData;
    timelineChart.update();
  }
}

function renderSeverityChart(severityCounts) {
  const low = severityCounts.LOW || 0;
  const high = severityCounts.HIGH || 0;

  if (!severityChart) {
    const ctx = document.getElementById("severityChart").getContext("2d");
    severityChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Low", "High"],
        datasets: [
          {
            data: [low, high],
            backgroundColor: ["#059669", "#dc2626"],
            borderWidth: 2,
            borderColor: "#ffffff",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#334155", boxWidth: 12 } },
        },
      },
    });
  } else {
    severityChart.data.datasets[0].data = [low, high];
    severityChart.update();
  }
}

function renderTopSources(sources) {
  const container = document.getElementById("topSources");

  if (!sources.length) {
    container.innerHTML = `<div class="empty">No data yet.</div>`;
    return;
  }

  const maxCount = Math.max(...sources.map((s) => s.count));

  container.innerHTML = sources
    .map((s) => {
      const pct = maxCount ? Math.round((s.count / maxCount) * 100) : 0;
      return `
        <div class="source-row">
          <span class="source-ip">${s.ip}</span>
          <span class="source-bar-track">
            <span class="source-bar-fill" style="width:${pct}%"></span>
          </span>
          <span class="source-count">${s.count}</span>
        </div>
      `;
    })
    .join("");
}

function renderAlertsTable(rows) {
  const tbody = document.getElementById("alertsBody");

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No alerts yet.</td></tr>`;
    lastAlertCount = 0;
    return;
  }

  const isNewData = rows.length !== lastAlertCount;

  tbody.innerHTML = rows
    .map((row, i) => {
      const predClass = row.prediction === "Benign" ? "pred-Benign" : "pred-attack";
      const sevClass = row.severity === "HIGH" ? "sev-HIGH" : "sev-LOW";
      const rowClass = i === 0 && isNewData ? "new-row" : "";
      return `
        <tr class="${rowClass}">
          <td>${row.timestamp || ""}</td>
          <td class="${predClass}">${row.prediction || ""}</td>
          <td><span class="${sevClass}">${row.severity || ""}</span></td>
          <td>${row.source_ip || ""}</td>
          <td>${row.destination_ip || ""}</td>
          <td>${row.packets || ""}</td>
        </tr>
      `;
    })
    .join("");

  lastAlertCount = rows.length;
}

fetchAlerts();
setInterval(fetchAlerts, POLL_INTERVAL_MS);
