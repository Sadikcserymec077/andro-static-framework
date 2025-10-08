// static/js/status.js
document.addEventListener("DOMContentLoaded", function () {
    const badge = document.getElementById("mobsf-status-badge");
    if (!badge) return;
  
    async function updateStatus() {
      try {
        const res = await fetch("/status", { cache: "no-store" });
        if (!res.ok) throw new Error("network");
        const j = await res.json();
        if (j.mobsf === "ok") {
          badge.className = "badge-status ok";
          badge.innerHTML = "🟢 MobSF Connected";
        } else if (j.mobsf === "down" || j.mobsf === "error") {
          badge.className = "badge-status down";
          badge.innerHTML = "🔴 MobSF Unreachable";
        } else {
          badge.className = "badge-status unknown";
          badge.innerHTML = "⚪ MobSF Unknown";
        }
      } catch (e) {
        badge.className = "badge-status down";
        badge.innerHTML = "🔴 MobSF Unreachable";
      }
    }
  
    // initial and interval
    updateStatus();
    setInterval(updateStatus, 5000); // poll every 5s
  });
  