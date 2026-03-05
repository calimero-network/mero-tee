const releaseTagInput = document.getElementById("releaseTag");
const repoSlugInput = document.getElementById("repoSlug");
const progressText = document.getElementById("progressText");
const progressBar = document.getElementById("progressBar");
const stepChecks = [...document.querySelectorAll(".step-check")];
const tabButtons = [...document.querySelectorAll(".tab")];
const tabContents = [...document.querySelectorAll(".tab-content")];

const storageKey = "mero-tee-verify-progress-v1";

function replacements() {
  const tag = releaseTagInput.value.trim() || "2.1.10";
  const repo = repoSlugInput.value.trim() || "calimero-network/mero-tee";
  return { tag, repo };
}

function renderCommands() {
  const { tag, repo } = replacements();
  document.querySelectorAll("[data-cmd]").forEach((el) => {
    const raw = el.getAttribute("data-cmd");
    const cmd = raw.replaceAll("__TAG__", tag).replaceAll("__REPO__", repo);
    el.textContent = cmd;
  });

  document.getElementById("kmsReleaseLink").href =
    `https://github.com/${repo}/releases/tag/${tag}`;
  document.getElementById("lockedReleaseLink").href =
    `https://github.com/${repo}/releases/tag/locked-image-v${tag}`;
}

function updateProgress() {
  const done = stepChecks.filter((c) => c.checked).length;
  const total = stepChecks.length;
  const pct = total === 0 ? 0 : Math.round((done / total) * 100);
  progressText.textContent = `${done} / ${total} complete`;
  progressBar.style.width = `${pct}%`;
}

function saveState() {
  const state = {
    tag: releaseTagInput.value,
    repo: repoSlugInput.value,
    checks: stepChecks.map((c) => c.checked),
  };
  localStorage.setItem(storageKey, JSON.stringify(state));
}

function loadState() {
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return;
    const state = JSON.parse(raw);
    if (typeof state.tag === "string") releaseTagInput.value = state.tag;
    if (typeof state.repo === "string") repoSlugInput.value = state.repo;
    if (Array.isArray(state.checks)) {
      stepChecks.forEach((c, idx) => {
        c.checked = Boolean(state.checks[idx]);
      });
    }
  } catch (_) {
    // Ignore malformed local storage.
  }
}

function setupCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const pre = btn.parentElement.querySelector("pre");
      if (!pre) return;
      const text = pre.textContent || "";
      try {
        await navigator.clipboard.writeText(text);
        const old = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = old;
        }, 900);
      } catch (_) {
        btn.textContent = "Copy failed";
      }
    });
  });
}

function setupTabs() {
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-tab");
      tabButtons.forEach((b) => b.classList.toggle("active", b === btn));
      tabContents.forEach((c) => {
        c.classList.toggle("hidden", c.id !== target);
      });
    });
  });
}

document.getElementById("expandAll").addEventListener("click", () => {
  document.querySelectorAll("details").forEach((d) => (d.open = true));
});

document.getElementById("collapseAll").addEventListener("click", () => {
  document.querySelectorAll("details").forEach((d) => (d.open = false));
});

document.getElementById("resetProgress").addEventListener("click", () => {
  stepChecks.forEach((c) => (c.checked = false));
  updateProgress();
  saveState();
});

[releaseTagInput, repoSlugInput].forEach((el) => {
  el.addEventListener("input", () => {
    renderCommands();
    saveState();
  });
});

stepChecks.forEach((c) => {
  c.addEventListener("change", () => {
    updateProgress();
    saveState();
  });
});

loadState();
renderCommands();
updateProgress();
setupCopyButtons();
setupTabs();
