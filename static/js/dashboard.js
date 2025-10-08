// static/js/dashboard.js
document.addEventListener("DOMContentLoaded", function () {
  const data = {
    labels: ["High", "Medium", "Low", "Info"],
    datasets: [{
      data: [
        window.SEVERITY_COUNTS.High || 0,
        window.SEVERITY_COUNTS.Medium || 0,
        window.SEVERITY_COUNTS.Low || 0,
        window.SEVERITY_COUNTS.Info || 0
      ],
      backgroundColor: [
        "rgba(220,53,69,0.85)",
        "rgba(255,193,7,0.85)",
        "rgba(13,110,253,0.85)",
        "rgba(108,117,125,0.85)"
      ],
      hoverOffset: 6
    }]
  };

  const ctx = document.getElementById("severityChart");
  if (ctx) {
    new Chart(ctx, {
      type: "doughnut",
      data: data,
      options: {
        responsive: true,
        plugins: { legend: { position: "bottom" } }
      }
    });
  }

  const filter = document.getElementById("severityFilter");
  if (filter) {
    filter.addEventListener("change", function () {
      const val = filter.value;
      const rows = document.querySelectorAll("#vulnTbody tr");
      rows.forEach(r => {
        const sev = (r.getAttribute("data-severity") || "Info").trim();
        if (val === "All" || sev.toLowerCase() === val.toLowerCase()) r.style.display = "";
        else r.style.display = "none";
      });
    });
  }
});
