(function () {
  document.querySelectorAll("#delete-form, #cancel-sub-form").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!confirm("Are you sure?")) e.preventDefault();
    });
  });

  var el = document.getElementById("scan");
  if (!el) return;
  var status = el.dataset.status;
  if (status !== "queued" && status !== "running") return;

  var started = Date.now();
  var pill = document.getElementById("status-pill");
  var title = document.getElementById("progress-title");
  var live = document.getElementById("live-count");
  var elapsed = document.getElementById("elapsed");

  setInterval(function () {
    var s = Math.floor((Date.now() - started) / 1000);
    elapsed.textContent = (s >= 60 ? Math.floor(s / 60) + "m " : "") + (s % 60) + "s";
  }, 1000);

  function poll() {
    fetch(el.dataset.statusUrl, { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        pill.textContent = d.status;
        pill.className = "status status-" + d.status;
        live.textContent = d.findings;
        if (d.status === "queued") {
          title.textContent = "Waiting in queue… (position " + d.queue_position + ")";
        } else if (d.status === "running") {
          title.textContent = "Nuclei scan in progress…";
        } else {
          window.location.reload();
          return;
        }
        setTimeout(poll, 3000);
      })
      .catch(function () { setTimeout(poll, 5000); });
  }
  poll();
})();
