// gmail_original_cs.js — auto analyze on "Mostrar original"

(function () {
  const params = new URLSearchParams(location.search);
  const isOriginal = params.get("view") === "om";
  if (!isOriginal) return;

  function extractHeaders() {
    const pre = document.querySelector("pre");
    const bodyText = pre ? pre.textContent : document.body?.innerText || "";
    if (!bodyText) return "";
    const parts = bodyText.split(/\r?\n\r?\n/);
    const headerBlock = parts[0] || bodyText;
    return headerBlock.trim();
  }

  function injectBanner({ score = 0 } = {}) {
    const color = score >= 70 ? "#DC2626" : score >= 40 ? "#D97706" : "#16A34A";
    const text = score >= 70 ? "Malicioso" : score >= 40 ? "Sospechoso" : "No malicioso";

    if (document.getElementById("hg-banner")) return;

    const wrap = document.createElement("div");
    wrap.id = "hg-banner";
    wrap.style.all = "initial";
    wrap.style.position = "fixed";
    wrap.style.top = "16px";
    wrap.style.right = "16px";
    wrap.style.zIndex = "2147483647";
    wrap.style.fontFamily = "system-ui,Segoe UI,Roboto,Arial,sans-serif";

    wrap.innerHTML = `
      <div style="background:#111827;color:#E5E7EB;border-radius:14px;box-shadow:0 8px 28px rgba(0,0,0,.35);min-width:300px;max-width:360px;overflow:hidden;border:1px solid #1f2937">
        <div style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-bottom:1px solid #1f2937">
          <div style="width:10px;height:10px;border-radius:999px;background:${color}"></div>
          <div style="font-weight:700">HeaderGuard</div>
          <div style="margin-left:auto;font-weight:700;color:${color}">${text}</div>
        </div>
        <div style="padding:12px">
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
            <div style="font-size:28px;font-weight:800">${Math.round(score)}</div>
            <div style="flex:1;height:10px;background:#1f2937;border-radius:999px;overflow:hidden">
              <div style="height:100%;width:${Math.max(0, Math.min(100, score))}%;background:${color}"></div>
            </div>
          </div>
          <div style="display:flex;gap:8px">
            <button id="hg-close" style="all:unset;background:#334155;color:#E5E7EB;padding:8px 10px;border-radius:10px;text-align:center;flex:1;cursor:pointer">Cerrar</button>
            <button id="hg-more" style="all:unset;background:#2563EB;color:white;padding:8px 10px;border-radius:10px;text-align:center;flex:1;cursor:pointer">Más info</button>
          </div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(wrap);

    wrap.querySelector("#hg-close").addEventListener("click", () => wrap.remove());
    wrap.querySelector("#hg-more").addEventListener("click", () => {
      const url = chrome.runtime.getURL("report.html");
      window.open(url, "_blank", "noopener");
    });
  }

  async function init() {
    // 1) Análisis de encabezados (score inicial)
    const headers = extractHeaders();
    if (headers) {
      chrome.runtime.sendMessage(
        { type: "analyzeHeaders", data: headers },
        (res) => {
          if (res && res.report) {
            injectBanner(res.report);
          }
        }
      );
    }

    // 2) Análisis de cuerpo por IA (módulo body_analyzer.js)
    try {
      const mod = await import(chrome.runtime.getURL("body_analyzer.js"));
      if (mod && typeof mod.analyzeOriginalBodyAndLog === "function") {
        mod.analyzeOriginalBodyAndLog();
      }
    } catch (err) {
      console.error("[HeaderGuard body] No se pudo cargar body_analyzer.js", err);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
