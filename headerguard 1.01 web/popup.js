// popup.js — show all checks with icons
function badgeFor(score){ if(score>=70) return {text:"Malicioso",cls:"bad"}; if(score>=40) return {text:"Sospechoso",cls:"warn"}; return {text:"No malicioso",cls:"ok"}; }
function barColor(score){ if(score>=70) return "var(--bad)"; if(score>=40) return "var(--warn)"; return "var(--ok)"; }
function icon(status){ if(status==="good") return "✔️"; if(status==="warn") return "⚠️"; if(status==="bad") return "❌"; return "ℹ️"; }
async function getLatestReport(){ const res = await chrome.runtime.sendMessage({type:"getLatestReport"}); return res?.report || null; }
async function reanalyzeActive(){ const [tab] = await chrome.tabs.query({active:true, currentWindow:true}); const res = await chrome.runtime.sendMessage({type:"reanalyzeActiveTab", tabId: tab?.id}); return res?.report || null; }
function fill(report){
  const badge = document.getElementById("badge");
  const {score=0, checks=[]} = report || {};
  const {text, cls} = badgeFor(score);
  badge.textContent = text; badge.className = "badge " + cls;
  const bar = document.getElementById("bar"); bar.style.width = Math.max(0, Math.min(100, score)) + "%"; bar.style.background = barColor(score);
  document.getElementById("scoreNum").textContent = Math.round(score);
  document.getElementById("classif").textContent = text;
  document.getElementById("risksCount").textContent = checks.length;
  const ul = document.getElementById("reasons"); ul.innerHTML = "";
  if(!checks.length){ const li=document.createElement("li"); li.className="empty"; li.textContent="Sin señales disponibles."; ul.appendChild(li); }
  else {
    checks.slice(0,8).forEach(c=>{ const li=document.createElement("li"); li.textContent = `${icon(c.status)} ${c.label} — ${c.details||""}`; ul.appendChild(li); });
    if(checks.length>8){ const li=document.createElement("li"); li.textContent = `(+${checks.length-8} más...)`; ul.appendChild(li); }
  }
}
document.getElementById("more").addEventListener("click", ()=>{ const url = chrome.runtime.getURL("report.html"); chrome.tabs.create({url}); });
document.getElementById("reanalyze").addEventListener("click", async ()=>{ const r = await reanalyzeActive(); if(r) fill(r); });
const toggleBtn = document.getElementById("togglePaste"); const pastePanel = document.getElementById("pastePanel"); const headersInput = document.getElementById("headersInput");
document.getElementById("clearPaste").addEventListener("click", ()=>{ headersInput.value = ""; headersInput.focus(); });
document.getElementById("analyzePaste").addEventListener("click", async ()=>{ const txt = headersInput.value.trim(); if(!txt) return; const res = await chrome.runtime.sendMessage({type:"analyzeHeaders", data: txt}); if(res?.report) fill(res.report); });
toggleBtn.addEventListener("click", ()=>{ pastePanel.classList.toggle("hidden"); if(!pastePanel.classList.contains("hidden")) headersInput.focus(); });
getLatestReport().then(r => { if(r) fill(r); });
