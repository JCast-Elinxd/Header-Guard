// report.js — reporte centrado + guía educativa (sin sección de señales)
function badgeFor(score) { if (score >= 70) return { text: "Malicioso", cls: "bad" }; if (score >= 40) return { text: "Sospechoso", cls: "warn" }; return { text: "No malicioso", cls: "ok" }; }
async function getLatestReport() { const res = await chrome.runtime.sendMessage({ type: "getLatestReport" }); return res?.report || null; }

// ---------- Mapeo educativo ----------
const EDU = [
  {
    key: "spf",
    title: "SPF (Sender Policy Framework)",
    why: "Valida si el servidor que envía está autorizado por el dominio del remitente.",
    categories: [
      { code: "PASS", label: "PASS", cls: "good", desc: "El servidor está autorizado por la política SPF del dominio." },
      { code: "SOFTFAIL/NEUTRAL", label: "SOFTFAIL / NEUTRAL", cls: "warn", desc: "El dominio no autoriza explícitamente este servidor." },
      { code: "FAIL", label: "FAIL", cls: "bad", desc: "El servidor NO está autorizado por la política SPF." },
      { code: "NONE/ERROR", label: "NONE / TEMPERROR / PERMERROR", cls: "info", desc: "Sin política SPF o hubo un error." },
    ]
  },
  {
    key: "dkim",
    title: "DKIM (DomainKeys Identified Mail)",
    why: "Firma digital del mensaje; garantiza integridad y autenticidad.",
    categories: [
      { code: "PASS", label: "PASS", cls: "good", desc: "La firma es válida y coincide con el dominio firmante." },
      { code: "NONE", label: "NONE", cls: "warn", desc: "El mensaje no fue firmado." },
      { code: "FAIL", label: "FAIL", cls: "bad", desc: "Firma inválida o contenido alterado." },
    ]
  },
  {
    key: "dmarc",
    title: "DMARC (Domain-based Message Authentication, Reporting & Conformance)",
    why: "Define qué hacer si SPF/DKIM fallan; exige alineamiento con el dominio del From.",
    categories: [
      { code: "PASS", label: "PASS", cls: "good", desc: "Se cumple DMARC (SPF o DKIM alinean)." },
      { code: "FAIL", label: "FAIL", cls: "bad", desc: "No se cumple DMARC (sin alineamiento)." },
      { code: "NONE", label: "NONE", cls: "info", desc: "No hubo verificación DMARC en Authentication-Results." },
    ],
    extraKey: "dmarc_policy",
    extraTitle: "Política DMARC (p=)",
    extraExplain: "Política publicada por el dominio en _dmarc.domain:",
    extraLevels: [
      { code: "REJECT", label: "p=reject", cls: "bad", desc: "Rechazar mensajes no autenticados." },
      { code: "QUARANTINE", label: "p=quarantine", cls: "warn", desc: "Enviar a spam los dudosos." },
      { code: "NONE", label: "p=none", cls: "info", desc: "Solo monitoreo (sin acción)." },
    ]
  },
  {
    key: "from_vs_return",
    title: "From vs Envelope-From (Return-Path)",
    why: "Compara el dominio visible al usuario con el dominio técnico que envió.",
    categories: [
      { code: "MATCH", label: "Coinciden / Relacionados", cls: "good", desc: "From y envelope coinciden o son del mismo grupo." },
      { code: "MISMATCH", label: "Distintos", cls: "warn", desc: "Diferentes (puede ser legítimo si usa un ESP), revisar." },
    ]
  },
  {
    key: "reply_to",
    title: "Reply-To",
    why: "Puede usarse para redirigir respuestas a atacantes.",
    categories: [
      { code: "MATCH", label: "Coincide/Relacionado", cls: "good", desc: "Reply-To alineado con From." },
      { code: "DIFF", label: "Distinto", cls: "warn", desc: "Dominio diferente. Revisar legitimidad." },
      { code: "NONE", label: "No especificado", cls: "info", desc: "No se proporcionó Reply-To." },
    ]
  },
  {
    key: "received_chain",
    title: "Cadena Received",
    why: "Muestra el recorrido del mensaje; origen privado/inconsistente es señal de alerta.",
    categories: [
      { code: "OK", label: "Origen público coherente", cls: "good", desc: "Cadena normal." },
      { code: "PRIVATE", label: "Origen privado/interno", cls: "warn", desc: "IP de origen privada o no trazable." },
      { code: "NONE", label: "Sin líneas Received", cls: "info", desc: "No se detectaron líneas Received." },
    ]
  },
  {
    key: "helo",
    title: "HELO/EHLO",
    why: "El saludo del servidor debe ser un host válido.",
    categories: [
      { code: "OK", label: "Dominio válido", cls: "good", desc: "El saludo parece correcto." },
      { code: "SUS", label: "Localhost/IP literal", cls: "warn", desc: "Configuración dudosa." },
      { code: "NONE", label: "No encontrado", cls: "info", desc: "No se encontró saludo." },
    ]
  },
  {
    key: "dns",
    title: "DNS (MX/SPF/DMARC/DKIM TXT)",
    why: "Un dominio serio publica registros de correo y DKIM (selector TXT).",
    categories: [
      { code: "OK", label: "Registros presentes", cls: "good", desc: "Se encontraron registros necesarios." },
      { code: "MISSING", label: "Faltan registros", cls: "warn", desc: "Algún registro no existe o está incompleto." },
      { code: "N/A", label: "No se pudo consultar", cls: "info", desc: "Sin dominio o error de consulta." },
    ]
  },
  {
    key: "align",
    title: "Alineamiento (SPF/DKIM/DMARC)",
    why: "Para DMARC, al menos SPF o DKIM deben alinear con el dominio del From.",
    categories: [
      { code: "OK", label: "Alinea", cls: "good", desc: "Alineamiento logrado." },
      { code: "NO", label: "No alinea", cls: "warn", desc: "SPF y DKIM no alinean con From." },
    ]
  },
  {
    key: "time",
    title: "Tiempos en Received",
    why: "Las marcas deberían aumentar; inconsistencias pueden ser manipulación.",
    categories: [
      { code: "OK", label: "Coherente", cls: "good", desc: "Marcas avanzan correctamente." },
      { code: "BAD", label: "Inconsistente", cls: "warn", desc: "Saltos hacia atrás detectados." },
      { code: "NONE", label: "No detectado", cls: "info", desc: "No se pudo evaluar." },
    ]
  },
  {
    key: "dups",
    title: "Headers duplicados",
    why: "Duplicados de headers críticos pueden intentar confundir validadores.",
    categories: [
      { code: "OK", label: "Sin duplicados", cls: "good", desc: "No hay duplicados relevantes." },
      { code: "HAS", label: "Duplicados", cls: "warn", desc: "Se encontraron duplicados relevantes." },
    ]
  },
  {
    key: "subject",
    title: "Asunto sensible",
    why: "Lenguaje de urgencia/financiero típico en phishing.",
    categories: [
      { code: "OK", label: "Sin señales", cls: "good", desc: "El asunto no contiene lenguaje de riesgo." },
      { code: "SUS", label: "Lenguaje sensible", cls: "warn", desc: "Se detectaron palabras típicas de phishing." },
    ]
  },
];

// ---------- Utilidades ----------
function getCheck(report, key) {
  return (report.checks || []).find(c => c.key === key) || null;
}
function statusToCategoryForSPF(val) {
  if (!val) return "NONE/ERROR";
  const v = String(val).toUpperCase();
  if (v === "PASS") return "PASS";
  if (v === "FAIL") return "FAIL";
  if (v.includes("SOFTFAIL") || v.includes("NEUTRAL")) return "SOFTFAIL/NEUTRAL";
  return "NONE/ERROR";
}

// ---------- Render básico (chips, resumen, encabezados) ----------
function fillBasics(r) {
  const meta = document.getElementById("meta"); meta.innerHTML = "";
  const chips = [
    ["Remitente", r.summary?.from || "—"],
    ["Return-Path", r.summary?.returnPath || "—"],
    ["SPF", r.summary?.spf || "—"],
    ["DKIM", r.summary?.dkim || "—"],
    ["DMARC", r.summary?.dmarc || "—"]
  ];
  
  // Agregar chip de análisis ML si existe
  if (r.bodyAnalysis) {
    chips.push(["Análisis ML", r.bodyAnalysis.resultado.veredicto]);
  }
  
  chips.forEach(([k, v]) => {
    const div = document.createElement("div"); div.className = "chip"; div.textContent = `${k}: ${v}`; meta.appendChild(div);
  });
  
  document.getElementById("score").textContent = Math.round(r.score);
  document.getElementById("cls").textContent = badgeFor(r.score).text;
  document.getElementById("date").textContent = new Date(r.createdAt || Date.now()).toLocaleString();
  document.getElementById("raw").textContent = r.raw || "";
  
  // Agregar sección de análisis del cuerpo si existe
  if (r.bodyAnalysis) {
    const container = document.querySelector('.container');
    const bodyAnalysisCard = document.createElement('div');
    bodyAnalysisCard.className = 'card';
    bodyAnalysisCard.innerHTML = `
      <h3 style="text-align:center;margin-top:0">Análisis de Contenido (ML)</h3>
      <div class="kv">
        <div class="k">Veredicto</div>
        <div>${r.bodyAnalysis.resultado.veredicto}</div>
        <div class="k">Probabilidad</div>
        <div>${r.bodyAnalysis.resultado.probabilidad_phishing}</div>
        <div class="k">Alertas</div>
        <div>${r.bodyAnalysis.resultado.alertas_detectadas}</div>
      </div>
      ${r.bodyAnalysis.analisis_heuristico.alertas.length > 0 ? `
        <div style="margin-top:12px">
          <strong>Alertas heurísticas:</strong>
          <ul style="margin:8px 0 0 20px">
            ${r.bodyAnalysis.analisis_heuristico.alertas.map(alert => `<li>${alert}</li>`).join('')}
          </ul>
        </div>
      ` : ''}
    `;
    
    // Insertar antes de la sección de encabezados
    const headersCard = document.querySelector('.card:last-child');
    container.insertBefore(bodyAnalysisCard, headersCard);
  }
}

// ---------- Menú educativa ----------
function renderEdu(report) {
  const eduMenu = document.getElementById("eduMenu");
  const eduContent = document.getElementById("eduContent");
  eduMenu.innerHTML = ""; eduContent.innerHTML = "Selecciona un tema del menú para ver la explicación.";

  const current = {
    spf: () => statusToCategoryForSPF(report.summary?.spf),
    dkim: () => (report.summary?.dkim || "").toUpperCase() || "NONE",
    dmarc: () => (report.summary?.dmarc || "").toUpperCase() || "NONE",
    from_vs_return: () => {
      const c = getCheck(report, "from_vs_return"); if (!c) return "MISMATCH";
      return c.status === "good" ? "MATCH" : "MISMATCH";
    },
    reply_to: () => {
      const c = getCheck(report, "reply_to"); if (!c) return "NONE";
      if (c.status === "info") return "NONE";
      return c.status === "good" ? "MATCH" : "DIFF";
    },
    received_chain: () => {
      const c = getCheck(report, "received_chain"); if (!c) return "NONE";
      if (c.status === "info") return "NONE";
      return (c.details || "").includes("privado") ? "PRIVATE" : "OK";
    },
    helo: () => {
      const c = getCheck(report, "helo"); if (!c) return "NONE";
      if (c.status === "info") return "NONE";
      return c.status === "good" ? "OK" : "SUS";
    },
    dns: () => {
      const mx = getCheck(report, "mx");
      const spf = getCheck(report, "spf_dns");
      const dm = getCheck(report, "dmarc_dns");
      const anyWarn = [mx, spf, dm].some(x => x && x.status === "warn");
      if ([mx, spf, dm].every(x => x && x.status !== "info") && !anyWarn) return "OK";
      if (anyWarn) return "MISSING";
      return "N/A";
    },
    align: () => {
      const dmarcAl = getCheck(report, "align_dmarc");
      return dmarcAl && dmarcAl.status === "good" ? "OK" : "NO";
    },
    time: () => {
      const c = getCheck(report, "time"); if (!c) return "NONE";
      if (c.status === "info") return "NONE";
      return c.status === "good" ? "OK" : "BAD";
    },
    dups: () => {
      const c = getCheck(report, "dups"); if (!c) return "OK";
      return c.status === "good" ? "OK" : "HAS";
    },
    subject: () => {
      const c = getCheck(report, "subject"); if (!c) return "OK";
      return c.status === "good" ? "OK" : "SUS";
    }
  };

  EDU.forEach((section, idx) => {
    const btn = document.createElement("button");
    btn.textContent = section.title;
    btn.addEventListener("click", () => openSection(section, btn));
    if (idx === 0) btn.classList.add("active");
    eduMenu.appendChild(btn);
  });

  if (EDU[0]) openSection(EDU[0], eduMenu.querySelector("button"));

  function openSection(section, btn) {
    [...eduMenu.querySelectorAll("button")].forEach(b => b.classList.remove("active"));
    btn.classList.add("active");

    let curCode = "—";
    try {
      switch (section.key) {
        case "spf": curCode = current.spf(); break;
        case "dkim": curCode = current.dkim(); break;
        case "dmarc": curCode = current.dmarc(); break;
        case "from_vs_return": curCode = current.from_vs_return(); break;
        case "reply_to": curCode = current.reply_to(); break;
        case "received_chain": curCode = current.received_chain(); break;
        case "helo": curCode = current.helo(); break;
        case "dns": curCode = current.dns(); break;
        case "align": curCode = current.align(); break;
        case "time": curCode = current.time(); break;
        case "dups": curCode = current.dups(); break;
        case "subject": curCode = current.subject(); break;
      }
    } catch (e) { }

    eduContent.innerHTML = `
      <h4 style="margin:0 0 8px 0">${section.title}</h4>
      <p style="margin:0 0 12px 0">${section.why}</p>
      <div style="margin:6px 0 10px 0; color:#9ca3af">Resultado para este correo: <b>${curCode}</b></div>
      <div>${section.categories.map(cat => {
      const isHit =
        (cat.code === curCode) ||
        (section.key === "spf" && cat.code === "SOFTFAIL/NEUTRAL" && (curCode || "").includes("SOFTFAIL")) ||
        (section.key === "spf" && cat.code === "SOFTFAIL/NEUTRAL" && (curCode || "").includes("NEUTRAL")) ||
        (section.key === "dmarc" && cat.code === "NONE" && (curCode || "") !== "PASS" && (curCode || "") !== "FAIL");
      return `<span class="pill ${cat.cls} ${isHit ? 'hit' : ''}">${cat.label}</span>`;
    }).join("")}</div>
      <div style="margin-top:10px">${section.categories.map(cat => `
        <div style="margin:8px 0"><b>${cat.label}:</b> ${cat.desc}</div>
      `).join("")}</div>
      ${section.extraKey ? renderExtra(section) : ""}
    `;

    function renderExtra(s) {
      const pol = (getCheck(report, "dmarc_policy")?.details || "—").toUpperCase();
      const blocks = s.extraLevels.map(level => {
        const hit = pol.includes(level.code);
        return `<span class="pill ${level.cls} ${hit ? 'hit' : ''}">${level.label}</span>`;
      }).join("");
      const expl = s.extraLevels.map(l => `<div style="margin:6px 0"><b>${l.label}:</b> ${l.desc}</div>`).join("");
      return `
        <hr style="border:0;border-top:1px solid #1f2937;margin:14px 0">
        <div><b>${s.extraTitle}</b></div>
        <div style="color:#9ca3af; margin:6px 0 10px 0">${s.extraExplain}</div>
        <div>${blocks}</div>
        <div style="margin-top:10px">${expl}</div>
      `;
    }
  }
}

// ---------- Render completo ----------
function fill(r) {
  fillBasics(r);
  renderEdu(r);
}

getLatestReport().then(r => { if (r) fill(r); });
