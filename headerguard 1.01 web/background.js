// background.js — HeaderGuard (MV3) — advanced checks + DoH
console.log("🔧 HeaderGuard SW activo");

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const isPrivateIP = ip =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip) || ip === "127.0.0.1";

const domainOf = s =>
  (s?.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/)?.[1] || "").toLowerCase();

function relaxedAlign(a, b) {
  if (!a || !b) return false;
  a = a.toLowerCase();
  b = b.toLowerCase();
  return a === b || a.endsWith("." + b) || b.endsWith("." + a);
}

function unfoldHeader(raw, name) {
  const lines = (raw || "").split(/\r?\n/);
  const prefix = (name + ":").toLowerCase();
  let acc = [], capture = false;
  for (const line of lines) {
    const l = line || "", low = l.toLowerCase();
    if (!capture) {
      if (low.startsWith(prefix)) {
        acc.push(l.slice(prefix.length).trim());
        capture = true;
      }
    } else {
      if (/^[ \t]/.test(l)) {
        acc.push(l.trim());
      } else {
        break;
      }
    }
  }
  return acc.join(" ");
}

async function doh(name, type = "TXT") {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(res.status);
    return await res.json();
  } catch (e) {
    return null;
  }
}

function txtStrings(ans) {
  const a = ans?.Answer || [];
  return a
    .filter(x => x.type === 16)
    .map(x =>
      x.data.replace(/^"|"$/g, "").replace(/\\"/g, '"')
    );
}

function mxHosts(ans) {
  const a = ans?.Answer || [];
  return a
    .filter(x => x.type === 15)
    .map(x => x.data.split(" ").pop().replace(/\.$/, ""));
}

function parseAuthResults(authres) {
  const res = { spf: "?", dkim: "?", dmarc: "?", dkimDomains: [] };
  if (!authres) return res;

  const take = (text, name) => {
    const regex = new RegExp(
      name + "\\s*=\\s*(pass|fail|none|softfail|neutral|temperror|permerror)",
      "ig"
    );
    let m, all = [];
    while ((m = regex.exec(text))) {
      all.push((m[1] || "?").toUpperCase());
    }
    if (all.length) {
      res[name] = all.includes("PASS") ? "PASS" : all[0];
    }
  };

  take(authres, "spf");
  take(authres, "dkim");
  take(authres, "dmarc");

  let m;
  const dRe = /header\.i=\s*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/ig;
  while ((m = dRe.exec(authres))) {
    res.dkimDomains.push(m[1].toLowerCase());
  }

  return res;
}

function parseReceivedIPs(raw) {
  const ips = [];
  let m;

  const re1 = /Received:[^\n]*\[(\d{1,3}(?:\.\d{1,3}){3})\]/ig;
  while ((m = re1.exec(raw))) ips.push(m[1]);

  const re2 = /Received:.*?\bfrom\b.*?\b(\d{1,3}(?:\.\d{1,3}){3})/ig;
  while ((m = re2.exec(raw))) if (!ips.includes(m[1])) ips.push(m[1]);

  return ips;
}

function parseHeloEhlo(raw) {
  const re = /EHLO\s+([^\s;]+)|HELO\s+([^\s;]+)/ig, out = [];
  let m;
  while ((m = re.exec(raw))) out.push((m[1] || m[2] || "").toLowerCase());
  return out;
}

function parseReceivedDates(raw) {
  const lines = (raw.match(/^Received:.*$/gim) || []), dates = [];
  for (const l of lines) {
    const m = l.match(/;\s*(.+)$/);
    if (m) {
      const d = new Date(m[1]);
      if (!isNaN(d.getTime())) dates.push(d);
    }
  }
  return dates;
}

function duplicateHeaders(raw) {
  const names = ["From", "Subject", "To", "Date", "Message-ID"], dups = [];
  for (const n of names) {
    const c = (raw.match(new RegExp("^" + n + ":", "gim")) || []).length;
    if (c > 1) dups.push(`${n}×${c}`);
  }
  return dups;
}

async function forensicAnalyze(headersText) {
  const raw = (headersText || "").trim();
  const checks = [];
  let score = 0;
  const reasons = [];

  const from = unfoldHeader(raw, "From"),
    returnPath = unfoldHeader(raw, "Return-Path"),
    replyTo = unfoldHeader(raw, "Reply-To"),
    authres = unfoldHeader(raw, "Authentication-Results"),
    subject = unfoldHeader(raw, "Subject");

  const recvdIPs = parseReceivedIPs(raw),
    helo = parseHeloEhlo(raw),
    recvdDates = parseReceivedDates(raw),
    dupHdrs = duplicateHeaders(raw);

  const { spf, dkim, dmarc, dkimDomains } = parseAuthResults(authres);

  // SPF / DKIM / DMARC (Auth-Results)
  checks.push({
    key: "spf",
    label: "SPF (Auth-Results)",
    status: spf === "PASS" ? "good" : (spf === "?" ? "info" : "bad"),
    details: spf
  });
  if (spf === "FAIL" || spf === "NONE") {
    score += 35;
    reasons.push("SPF falló o ausente");
  }

  checks.push({
    key: "dkim",
    label: "DKIM (Auth-Results)",
    status: dkim === "PASS" ? "good" : (dkim === "?" ? "info" : "bad"),
    details: dkim + (dkimDomains.length ? ` (${dkimDomains.join(", ")})` : "")
  });
  if (dkim === "FAIL" || dkim === "NONE") {
    score += 30;
    reasons.push("DKIM falló o ausente");
  }

  checks.push({
    key: "dmarc",
    label: "DMARC (Auth-Results)",
    status: dmarc === "PASS" ? "good" : (dmarc === "?" ? "info" : "bad"),
    details: dmarc
  });
  if (dmarc === "FAIL" || dmarc === "NONE") {
    score += 25;
    reasons.push("DMARC falló o ausente");
  }

  // From vs Return-Path
  const dFrom = domainOf(from), dReturn = domainOf(returnPath);
  if (dFrom && dReturn && dFrom !== dReturn) {
    score += 20;
    reasons.push(`Dominio From (${dFrom}) ≠ Return-Path (${dReturn})`);
    checks.push({
      key: "from_vs_return",
      label: "From vs Return-Path",
      status: "warn",
      details: `${dFrom} vs ${dReturn}`
    });
  } else {
    checks.push({
      key: "from_vs_return",
      label: "From vs Return-Path",
      status: "good",
      details: dFrom || "—"
    });
  }

  // Reply-To
  const dReply = domainOf(replyTo);
  if (dReply && dFrom && !relaxedAlign(dReply, dFrom)) {
    checks.push({
      key: "reply_to",
      label: "Reply-To dominio",
      status: "warn",
      details: `${dReply} (≠ ${dFrom})`
    });
  } else if (dReply) {
    checks.push({
      key: "reply_to",
      label: "Reply-To dominio",
      status: "good",
      details: `${dReply}`
    });
  } else {
    checks.push({
      key: "reply_to",
      label: "Reply-To dominio",
      status: "info",
      details: "No especificado"
    });
  }

  // Cadena Received
  const hops = recvdIPs.length;
  const origin = recvdIPs[recvdIPs.length - 1] || "";
  if (origin && isPrivateIP(origin)) {
    checks.push({
      key: "received_chain",
      label: "Cadena Received",
      status: "warn",
      details: `${hops} hops; origen privado ${origin}`
    });
  } else {
    checks.push({
      key: "received_chain",
      label: "Cadena Received",
      status: hops ? "good" : "info",
      details: hops ? `${hops} hops; origen ${origin || "?"}` : "Sin 'Received' detectados"
    });
  }

  // HELO/EHLO
  if (helo.length) {
    const badHelo = helo.find(h =>
      h === "localhost" ||
      /^\[.*\]$/.test(h) ||
      /^\d{1,3}(\.\d{1,3}){3}$/.test(h)
    );
    checks.push({
      key: "helo",
      label: "HELO/EHLO",
      status: badHelo ? "warn" : "good",
      details: helo.join(", ")
    });
  } else {
    checks.push({
      key: "helo",
      label: "HELO/EHLO",
      status: "info",
      details: "No encontrado"
    });
  }

  // Orden de tiempos en Received
  let timeOk = true;
  for (let i = 1; i < recvdDates.length; i++) {
    if (recvdDates[i] < recvdDates[i - 1]) {
      timeOk = false;
      break;
    }
  }
  checks.push({
    key: "time",
    label: "Tiempos en Received",
    status: (recvdDates.length && timeOk) ? "good" : (recvdDates.length ? "warn" : "info"),
    details: recvdDates.length ? `${recvdDates.length} marcas` : "No detectado"
  });

  // Headers duplicados
  if (dupHdrs.length) {
    checks.push({
      key: "dups",
      label: "Headers duplicados",
      status: "warn",
      details: dupHdrs.join(", ")
    });
  } else {
    checks.push({
      key: "dups",
      label: "Headers duplicados",
      status: "good",
      details: "No"
    });
  }

  // Asunto sensible
  if (subject && /(urgent|verifica|verify|cuenta|contraseña|password|suspend|suspendida|invoice|factura|pago|transferencia|ganaste|premio)/i.test(subject)) {
    score += 10;
    reasons.push("Asunto contiene lenguaje de urgencia/sensible");
    checks.push({
      key: "subject",
      label: "Asunto sensible",
      status: "warn",
      details: subject.slice(0, 120)
    });
  } else {
    checks.push({
      key: "subject",
      label: "Asunto sensible",
      status: "good",
      details: "—"
    });
  }

  // DNS (MX / SPF / DMARC / DKIM)
  try {
    if (dFrom) {
      const mxj = await doh(dFrom, "MX");
      const mx = mxHosts(mxj);
      checks.push({
        key: "mx",
        label: "MX del dominio (From)",
        status: mx.length ? "good" : "warn",
        details: mx.length ? mx.join(", ") : "Sin MX"
      });

      const spfj = await doh(dFrom, "TXT");
      const spfTxt = txtStrings(spfj).filter(t => /v=spf1/i.test(t));
      checks.push({
        key: "spf_dns",
        label: "SPF (DNS TXT)",
        status: spfTxt.length ? "good" : "warn",
        details: spfTxt[0] || "Sin v=spf1"
      });

      const dmarcj = await doh(`_dmarc.${dFrom}`, "TXT");
      const dmarcTxt = txtStrings(dmarcj);
      if (dmarcTxt.length) {
        const pol = (dmarcTxt[0].match(/;\s*p\s*=\s*(none|quarantine|reject)/i)?.[1] || "?").toUpperCase();
        checks.push({
          key: "dmarc_dns",
          label: "DMARC (DNS TXT)",
          status: "good",
          details: dmarcTxt[0]
        });
        checks.push({
          key: "dmarc_policy",
          label: "DMARC p=",
          status: pol === "?" ? "info" : "good",
          details: pol
        });
      } else {
        checks.push({
          key: "dmarc_dns",
          label: "DMARC (DNS TXT)",
          status: "warn",
          details: `No existe _dmarc.${dFrom}`
        });
      }
    } else {
      checks.push({
        key: "mx",
        label: "MX del dominio (From)",
        status: "info",
        details: "Dominio no detectado"
      });
      checks.push({
        key: "spf_dns",
        label: "SPF (DNS TXT)",
        status: "info",
        details: "Dominio no detectado"
      });
      checks.push({
        key: "dmarc_dns",
        label: "DMARC (DNS TXT)",
        status: "info",
        details: "Dominio no detectado"
      });
    }

    // DKIM selectors
    const selRe = /header\.s=([A-Za-z0-9._-]+)/ig;
    let sels = [];
    let m;
    const authresFull = authres || "";
    while ((m = selRe.exec(authresFull))) {
      sels.push(m[1]);
    }
    if (sels.length) {
      let any = false;
      const dkimDom = (authresFull.match(/header\.i=\s*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/i)?.[1] || dFrom || "").toLowerCase();
      for (const s of sels) {
        const txtj = await doh(`${s}._domainkey.${dkimDom}`, "TXT");
        const txts = txtStrings(txtj);
        if (txts.length) any = true;
      }
      checks.push({
        key: "dkim_dns",
        label: "DKIM selector TXT",
        status: any ? "good" : "warn",
        details: sels.join(", ")
      });
    } else {
      checks.push({
        key: "dkim_dns",
        label: "DKIM selector TXT",
        status: "info",
        details: "No selector visible"
      });
    }
  } catch (e) {
    checks.push({
      key: "dns_error",
      label: "DNS (DoH)",
      status: "info",
      details: "Error de resolución"
    });
  }

  // Alineamiento SPF/DKIM/DMARC
  const spfAligned = spf === "PASS" && relaxedAlign(dReturn || "", dFrom || "");
  checks.push({
    key: "align_spf",
    label: "Alineamiento SPF",
    status: spfAligned ? "good" : "warn",
    details: `${dReturn || "?"} vs ${dFrom || "?"}`
  });

  const dkimAligned =
    dkim === "PASS" &&
    (
      (authres || "").toLowerCase().includes(`header.i=@${dFrom}`) ||
      (authres || "").toLowerCase().includes(`header.i=@${dFrom?.split(".").slice(-2).join(".")}`)
    );
  checks.push({
    key: "align_dkim",
    label: "Alineamiento DKIM",
    status: dkimAligned ? "good" : "warn",
    details: `${dFrom || "?"}`
  });

  const dmarcAligned = (spfAligned || dkimAligned);
  checks.push({
    key: "align_dmarc",
    label: "Alineamiento DMARC",
    status: dmarcAligned ? "good" : "warn",
    details: dmarcAligned ? "OK" : "No alinea"
  });

  score = Math.max(0, Math.min(100, score));
  const classification = score >= 70 ? "malicious" : score >= 40 ? "suspicious" : "clean";

  return {
    score,                // score basado en encabezados
    reasons,
    classification,
    summary: { from, returnPath, spf, dkim, dmarc },
    checks,
    raw,
    createdAt: Date.now()
  };
}

// --- Storage helpers ---
async function setLatestReport(report) {
  await chrome.storage.session.set({ lastReport: report });
}

async function getLatestReport() {
  const { lastReport } = await chrome.storage.session.get("lastReport");
  return lastReport || null;
}

// --- Llamada a la API externa desde el SW ---
async function analyzeBodyWithApi(texto) {
  const resp = await fetch("http://37.60.255.207:8000/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ text: texto })
  });

  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
  }

  return await resp.json();
}

// --- Combina score de encabezados + contenido ---
function combineScores(headerScore, contentProb) {
  const h = Number.isFinite(headerScore) ? headerScore : 0;
  const c = Number.isFinite(contentProb) ? contentProb : 0;
  // Estrategia simple: usamos el máximo de ambos riesgos
  return Math.max(h, c);
}

function classifyFromScore(score) {
  if (score >= 70) return "malicious";
  if (score >= 40) return "suspicious";
  return "clean";
}

// --- Mensajes ---
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === "analyzeHeaders") {
      const report = await forensicAnalyze(message.data || "");
      // guardamos también el score de encabezados por separado
      const full = {
        ...report,
        headerScore: report.score,
        contentScore: report.contentScore ?? null,
        contentVerdict: report.contentVerdict ?? null,
        contentRaw: report.contentRaw ?? null
      };
      await setLatestReport(full);
      sendResponse({ ok: true, report: full });
      return;
    }

    if (message?.type === "getLatestReport") {
      const report = await getLatestReport();
      sendResponse({ ok: true, report });
      return;
    }

    if (message?.type === "reanalyzeActiveTab") {
      const report = await getLatestReport();
      sendResponse({ ok: true, report });
      return;
    }

    // 🆕 análisis de cuerpo vía API + combinación
    if (message?.type === "analyzeBody") {
      try {
        const apiData = await analyzeBodyWithApi(message.text || "");

        const latest = await getLatestReport();
        const headerScore = latest?.headerScore ?? latest?.score ?? 0;

        // probabilidad_phishing viene como "10.05%"
        const probStr = apiData?.resultado?.probabilidad_phishing || "0%";
        const contentScore = parseFloat(String(probStr).replace("%", "")) || 0;

        const combinedScore = Math.max(0, Math.min(100, combineScores(headerScore, contentScore)));
        const classification = classifyFromScore(combinedScore);

        const combinedReport = {
          ...(latest || {}),
          score: combinedScore,            // 👈 este es el score "final" que verá la UI
          classification,
          headerScore,
          contentScore,
          contentVerdict: apiData?.resultado?.veredicto || null,
          contentAlerts: apiData?.resultado?.alertas_detectadas ?? null,
          contentRaw: apiData              // guardamos todo el JSON de la API
        };

        await setLatestReport(combinedReport);

        sendResponse({
          ok: true,
          data: apiData,
          combinedReport
        });
      } catch (e) {
        console.error("[HeaderGuard body] Error en background al llamar a la API:", e);
        sendResponse({ ok: false, error: String(e) });
      }
      return;
    }
  })();

  return true;
});

// --- Seed inicial para que el popup no salga vacío ---
(async () => {
  const c = await getLatestReport();
  if (!c) {
    const example = `Authentication-Results: mx.google.com;
      dkim=pass header.i=@example.com header.s=sel header.b=xyz;
      spf=pass smtp.mailfrom=user@example.com;
      dmarc=pass
From: "Example" <user@example.com>
Return-Path: <user@example.com>
Received: from relay.example.net (relay.example.net. [198.51.100.10]); Mon, 10 Nov 2025 12:00:00 -0800 (PST)`;
    const rep = await forensicAnalyze(example);
    await setLatestReport({ ...rep, headerScore: rep.score });
  }
})();
