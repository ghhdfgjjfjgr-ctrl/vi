const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const historyEl = document.getElementById("history");

const esc = (s) => String(s).replace(/[&<>"']/g, (m) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m]));

async function loadHistory() {
  const res = await fetch("/api/history");
  const rows = await res.json();
  if (!rows.length) {
    historyEl.innerHTML = `<div class="placeholder">ยังไม่พบประวัติการสแกน</div>`;
    return;
  }

  historyEl.innerHTML = rows
    .map(
      (r) => `<div class="history-item">
      <div><b>${esc(r.target)}</b> • mode=${esc(r.mode)} • risk=${r.risk_score}</div>
      <div>${esc(r.completed_at)}</div>
      <a href="/api/report/${r.id}.json" target="_blank">JSON</a>
      ${r.pdf_path ? ` • <a href="/api/report/${r.id}.pdf" target="_blank">PDF</a>` : " • PDF: unavailable"}
    </div>`
    )
    .join("");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = document.getElementById("target").value.trim();
  const mode = document.getElementById("mode").value;

  statusEl.textContent = "กำลังสแกน...";
  resultsEl.innerHTML = `<div class="placeholder">กำลังประมวลผลผลลัพธ์</div>`;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "scan failed");

    const v = data.vulnerabilities || [];
    resultsEl.innerHTML = `
      <div class="kpis">
        <div class="kpi">Hosts<b>${data.summary.hosts_discovered}</b></div>
        <div class="kpi">Open Ports<b>${data.summary.open_ports}</b></div>
        <div class="kpi">Findings<b>${data.summary.findings}</b></div>
        <div class="kpi">Risk Score<b>${data.summary.risk_score}/10</b></div>
      </div>
      <div class="download-links">
        <a href="/api/report/${data.scan_id}.json" target="_blank">ดาวน์โหลดรายงาน JSON</a>
        ${data.pdf_available ? ` • <a href="/api/report/${data.scan_id}.pdf" target="_blank">ดาวน์โหลดรายงาน PDF</a>` : " • PDF unavailable"}
      </div>
      ${data.pdf_notice ? `<div class="notice">${esc(data.pdf_notice)}</div>` : ""}
      <h3>ช่องโหว่ที่พบ</h3>
      ${v.length ? v.map((x)=>`<div class="vuln">[${esc(x.severity)}] ${esc(x.title)} • ${esc(x.cve)} • CVSS ${esc(x.cvss)} • ${esc(x.tool)} • Port ${esc(x.port)}</div>`).join("") : '<div class="placeholder">ไม่พบช่องโหว่จากการจำลอง</div>'}
    `;
    statusEl.textContent = "สแกนสำเร็จ";
    loadHistory();
  } catch (err) {
    statusEl.textContent = `เกิดข้อผิดพลาด: ${err.message}`;
    resultsEl.innerHTML = `<div class="placeholder">ไม่สามารถสแกนได้</div>`;
  }
});

loadHistory();
