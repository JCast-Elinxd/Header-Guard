// background.js
const STORAGE_KEY = "headerGuardReports";
const MAX_REPORTS = 50;

async function saveReport(report) {
  const data = await chrome.storage.local.get([STORAGE_KEY]);
  const reports = data[STORAGE_KEY] || [];
  
  reports.unshift({
    ...report,
    id: Date.now().toString()
  });
  
  if (reports.length > MAX_REPORTS) {
    reports.splice(MAX_REPORTS);
  }
  
  await chrome.storage.local.set({ [STORAGE_KEY]: reports });
  return report;
}

async function getLatestReport() {
  const data = await chrome.storage.local.get([STORAGE_KEY]);
  const reports = data[STORAGE_KEY] || [];
  return reports[0] || null;
}

// Función para analizar el cuerpo del email con el servidor Python
async function analyzeEmailBody(bodyText) {
  try {
    console.log("📡 Enviando cuerpo del email al servidor ML...");
    const response = await fetch('http://localhost:8000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text: bodyText })
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const result = await response.json();
    console.log("✅ Análisis ML completado:", result);
    return result;
  } catch (error) {
    console.error('❌ Error analyzing email body:', error);
    return null;
  }
}

// Análisis principal que combina headers y cuerpo
async function analyzeHeaders(headersText, emailBody = null) {
  console.log("🔍 Iniciando análisis de headers y cuerpo...");
  
  const report = {
    score: 0,
    checks: [],
    summary: {},
    raw: headersText,
    createdAt: Date.now(),
    bodyAnalysis: null
  };

  // ANÁLISIS DE HEADERS (tu código existente)
  try {
    const lines = headersText.split(/\r?\n/).filter(l => l.trim());
    const headers = {};
    let currentKey = "";

    lines.forEach(line => {
      if (line.match(/^\S/)) {
        const colon = line.indexOf(":");
        if (colon > 0) {
          currentKey = line.slice(0, colon).trim();
          const value = line.slice(colon + 1).trim();
          headers[currentKey] = value;
        }
      } else if (currentKey) {
        headers[currentKey] += " " + line.trim();
      }
    });

    // Resumen básico
    report.summary = {
      from: headers.From || headers.from || "—",
      returnPath: headers["Return-Path"] || "—",
      spf: extractSPF(headers),
      dkim: extractDKIM(headers),
      dmarc: extractDMARC(headers)
    };

    // Checks de seguridad
    const checks = [];

    // SPF
    const spfStatus = report.summary.spf?.toUpperCase() || "NONE";
    if (spfStatus === "PASS") {
      checks.push({ key: "spf", label: "SPF válido", status: "good", details: "El servidor está autorizado" });
    } else if (spfStatus === "FAIL") {
      checks.push({ key: "spf", label: "SPF inválido", status: "bad", details: "El servidor NO está autorizado" });
      report.score += 25;
    } else if (spfStatus.includes("SOFTFAIL") || spfStatus.includes("NEUTRAL")) {
      checks.push({ key: "spf", label: "SPF dudoso", status: "warn", details: "No autorizado explícitamente" });
      report.score += 10;
    } else {
      checks.push({ key: "spf", label: "Sin SPF", status: "info", details: "No se verificó SPF" });
      report.score += 5;
    }

    // DKIM
    const dkimStatus = report.summary.dkim?.toUpperCase() || "NONE";
    if (dkimStatus === "PASS") {
      checks.push({ key: "dkim", label: "DKIM válido", status: "good", details: "Firma digital correcta" });
    } else if (dkimStatus === "FAIL") {
      checks.push({ key: "dkim", label: "DKIM inválido", status: "bad", details: "Firma alterada o incorrecta" });
      report.score += 25;
    } else {
      checks.push({ key: "dkim", label: "Sin DKIM", status: "warn", details: "No firmado digitalmente" });
      report.score += 10;
    }

    // DMARC
    const dmarcStatus = report.summary.dmarc?.toUpperCase() || "NONE";
    if (dmarcStatus === "PASS") {
      checks.push({ key: "dmarc", label: "DMARC válido", status: "good", details: "Autenticación completa" });
    } else if (dmarcStatus === "FAIL") {
      checks.push({ key: "dmarc", label: "DMARC inválido", status: "bad", details: "Falla autenticación DMARC" });
      report.score += 30;
    } else {
      checks.push({ key: "dmarc", label: "Sin DMARC", status: "info", details: "No se verificó DMARC" });
      report.score += 5;
    }

    // From vs Return-Path
    const fromDomain = extractDomain(report.summary.from);
    const returnPathDomain = extractDomain(report.summary.returnPath);
    
    if (fromDomain && returnPathDomain && fromDomain === returnPathDomain) {
      checks.push({ key: "from_vs_return", label: "From y Return-Path coinciden", status: "good", details: "Dominios alineados" });
    } else if (fromDomain && returnPathDomain) {
      checks.push({ key: "from_vs_return", label: "From y Return-Path diferentes", status: "warn", details: "Posible suplantación" });
      report.score += 15;
    }

    // Reply-To
    const replyTo = headers["Reply-To"] || headers["reply-to"];
    if (replyTo) {
      const replyToDomain = extractDomain(replyTo);
      if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
        checks.push({ key: "reply_to", label: "Reply-To sospechoso", status: "warn", details: "Dominio diferente al From" });
        report.score += 10;
      }
    }

    // Received chain analysis
    const receivedHeaders = Object.entries(headers)
      .filter(([k]) => k.toLowerCase().startsWith("received"))
      .map(([_, v]) => v);
    
    if (receivedHeaders.length > 0) {
      checks.push({ key: "received_chain", label: "Cadena Received presente", status: "good", details: `${receivedHeaders.length} saltos` });
      
      // Detectar IPs privadas
      const privateIPs = receivedHeaders.filter(h => 
        h.match(/(10\.|192\.168|172\.(1[6-9]|2[0-9]|3[0-1])|127\.0|localhost)/)
      );
      if (privateIPs.length > 0) {
        checks.push({ key: "received_chain", label: "Origen privado detectado", status: "warn", details: "IP privada en cadena" });
        report.score += 10;
      }
    } else {
      checks.push({ key: "received_chain", label: "Sin cadena Received", status: "info", details: "No se encontraron headers Received" });
    }

    // HELO/EHLO analysis
    const heloMatch = headersText.match(/helo=?[^\s]+/i) || headersText.match(/ehlo=?[^\s]+/i);
    if (heloMatch) {
      const helo = heloMatch[0].toLowerCase();
      if (helo.includes("localhost") || helo.match(/\d+\.\d+\.\d+\.\d+/)) {
        checks.push({ key: "helo", label: "HELO/EHLO sospechoso", status: "warn", details: "Usa localhost o IP literal" });
        report.score += 5;
      }
    }

    // Duplicate headers
    const headerKeys = Object.keys(headers);
    const duplicates = headerKeys.filter(key => 
      headerKeys.filter(k => k.toLowerCase() === key.toLowerCase()).length > 1
    );
    if (duplicates.length > 0) {
      checks.push({ key: "dups", label: "Headers duplicados", status: "warn", details: `${duplicates.length} headers repetidos` });
      report.score += 8;
    }

    // Subject analysis
    const subject = headers.Subject || headers.subject || "";
    const suspiciousWords = ["urgente", "importante", "verific", "segur", "cuenta", "banco", "paypal", "contraseña", "password"];
    const hasSuspicious = suspiciousWords.some(word => 
      subject.toLowerCase().includes(word)
    );
    if (hasSuspicious) {
      checks.push({ key: "subject", label: "Asunto sospechoso", status: "warn", details: "Contiene lenguaje de phishing" });
      report.score += 12;
    }

    report.checks = checks;
    
    // Score base basado solo en headers
    const headerScore = Math.min(100, report.score);
    report.score = headerScore;

  } catch (error) {
    console.error("Error en análisis de headers:", error);
    report.checks.push({
      key: "analysis_error",
      label: "Error en análisis",
      status: "warn",
      details: "No se pudieron analizar todos los headers"
    });
  }

  // ANÁLISIS DEL CUERPO DEL EMAIL (nueva funcionalidad)
  if (emailBody && emailBody.trim().length > 0) {
    try {
      console.log("📧 Analizando cuerpo del email...");
      const bodyAnalysis = await analyzeEmailBody(emailBody);
      
      if (bodyAnalysis) {
        report.bodyAnalysis = bodyAnalysis;
        
        // Convertir probabilidad a número (ej: "85.00%" → 0.85)
        const phishingProb = parseFloat(bodyAnalysis.resultado.probabilidad_phishing) / 100;
        
        // Ponderar: 60% headers, 40% cuerpo
        const headerScore = report.score;
        const bodyScore = phishingProb * 100;
        
        // Combinar scores
        report.score = Math.min(100, (headerScore * 0.6) + (bodyScore * 0.4));
        
        // Agregar checks basados en el análisis del cuerpo
        if (bodyAnalysis.analisis_heuristico.alertas.length > 0) {
          report.checks.push({
            key: "body_heuristics",
            label: "Análisis heurístico del cuerpo",
            status: "bad",
            details: `${bodyAnalysis.analisis_heuristico.alertas.length} alertas detectadas`
          });
        }
        
        // Agregar veredicto del cuerpo como check
        const bodyStatus = bodyAnalysis.resultado.veredicto === "SEGURO" ? "good" : 
                          bodyAnalysis.resultado.veredicto === "SOSPECHOSO" ? "warn" : "bad";
        
        report.checks.push({
          key: "body_analysis",
          label: `Análisis ML del cuerpo: ${bodyAnalysis.resultado.veredicto}`,
          status: bodyStatus,
          details: `Probabilidad: ${bodyAnalysis.resultado.probabilidad_phishing} - ${bodyAnalysis.resultado.alertas_detectadas} alertas`
        });

        // Agregar información de URLs si existe
        if (bodyAnalysis.analisis_heuristico.detalle_urls && 
            bodyAnalysis.analisis_heuristico.detalle_urls.length > 0) {
          
          const maliciousUrls = bodyAnalysis.analisis_heuristico.detalle_urls.filter(
            url => parseFloat(url.riesgo_ia) > 0.3
          );
          
          if (maliciousUrls.length > 0) {
            report.checks.push({
              key: "malicious_urls",
              label: "Enlaces sospechosos detectados",
              status: "bad",
              details: `${maliciousUrls.length} enlaces con alto riesgo`
            });
          }
        }
      }
    } catch (error) {
      console.error('Error en análisis del cuerpo:', error);
      report.checks.push({
        key: "body_analysis_error",
        label: "Error en análisis del cuerpo",
        status: "warn",
        details: "No se pudo analizar el contenido del email"
      });
    }
  } else {
    report.checks.push({
      key: "no_body",
      label: "Sin cuerpo para analizar",
      status: "info",
      details: "No se encontró contenido del email"
    });
  }

  // Guardar reporte final
  await saveReport(report);
  console.log("✅ Análisis completado. Score final:", report.score);
  return report;
}

// Funciones auxiliares para análisis de headers
function extractSPF(headers) {
  const authResults = headers["Authentication-Results"] || "";
  const spfMatch = authResults.match(/spf=(\w+)/i);
  if (spfMatch) return spfMatch[1];
  
  const receivedSPF = headers["Received-SPF"] || "";
  const receivedMatch = receivedSPF.match(/\(([^)]+)\)/);
  if (receivedMatch) return receivedMatch[1];
  
  return "none";
}

function extractDKIM(headers) {
  const authResults = headers["Authentication-Results"] || "";
  const dkimMatch = authResults.match(/dkim=(\w+)/i);
  return dkimMatch ? dkimMatch[1] : "none";
}

function extractDMARC(headers) {
  const authResults = headers["Authentication-Results"] || "";
  const dmarcMatch = authResults.match(/dmarc=(\w+)/i);
  return dmarcMatch ? dmarcMatch[1] : "none";
}

function extractDomain(str) {
  if (!str) return null;
  const emailMatch = str.match(/@([^\s>]+)/);
  if (emailMatch) return emailMatch[1];
  
  const angleMatch = str.match(/<[^>]*@([^\s>]+)/);
  return angleMatch ? angleMatch[1] : null;
}

// Message handler principal
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("📨 Mensaje recibido:", message.type);
  
  switch (message.type) {
    case "analyzeHeaders":
      analyzeHeaders(message.data, message.emailBody)
        .then(report => {
          console.log("✅ Enviando reporte completo");
          sendResponse({ report });
        })
        .catch(error => {
          console.error("❌ Error en análisis:", error);
          sendResponse({ error: error.message });
        });
      return true;

    case "getLatestReport":
      getLatestReport()
        .then(report => sendResponse({ report }))
        .catch(error => sendResponse({ error: error.message }));
      return true;

    case "reanalyzeActiveTab":
      // Esta funcionalidad puede extenderse para incluir el cuerpo también
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.url?.includes("mail.google.com")) {
          chrome.tabs.sendMessage(tabs[0].id, { type: "extractHeadersAndBody" }, (response) => {
            if (response) {
              analyzeHeaders(response.headers, response.body)
                .then(report => sendResponse({ report }))
                .catch(error => sendResponse({ error: error.message }));
            }
          });
        }
      });
      return true;

    default:
      console.warn("Tipo de mensaje no reconocido:", message.type);
      sendResponse({ error: "Tipo de mensaje no reconocido" });
  }
});

// Mensaje de inicio
console.log("🚀 HeaderGuard Background Script ejecutándose...");