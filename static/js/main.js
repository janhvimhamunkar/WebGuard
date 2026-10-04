document.addEventListener("DOMContentLoaded", () => {
  const rings = document.querySelectorAll(".score-ring");
  rings.forEach(ring => {
    if (ring.hasAttribute("data-score")) {
        const s = +ring.dataset.score;
        ring.style.setProperty("--p", s);
        ring.style.setProperty("--c", s >= 90 ? "var(--pass)" : s >= 75 ? "var(--blue-primary)" : s >= 50 ? "var(--warn)" : s >= 25 ? "var(--high)" : "var(--crit)");
    } else if (ring.hasAttribute("data-risk-score")) {
        const s = +ring.dataset.riskScore;
        ring.style.setProperty("--p", s);
        ring.style.setProperty("--c", s <= 10 ? "var(--pass)" : s <= 25 ? "var(--blue-primary)" : s <= 50 ? "var(--warn)" : s <= 75 ? "var(--high)" : "var(--crit)");
    }
  });
  const btn = document.getElementById("scanBtn");
  if (!btn) return;
  const url = document.getElementById("url"), auth = document.getElementById("auth"), err = document.getElementById("err");
  auth.addEventListener("change", () => (btn.disabled = !auth.checked));
  const fail = m => { err.textContent = m; err.classList.remove("d-none");
    document.getElementById("scanForm").classList.remove("d-none"); document.getElementById("loading").classList.add("d-none"); };
  btn.addEventListener("click", async () => {
    err.classList.add("d-none");
    const v = url.value.trim();
    if (!/^https?:\/\/\S+$/i.test(v)) return fail("URL must start with http:// or https://");
    document.getElementById("scanForm").classList.add("d-none");
    document.getElementById("loading").classList.remove("d-none");
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: v, authorized: auth.checked }) });
      const d = await r.json();
      if (d.ok) window.location = d.redirect; else fail(d.error || "Scan failed.");
    } catch (e) { fail("Could not reach the WebGuard server."); }
  });
});
