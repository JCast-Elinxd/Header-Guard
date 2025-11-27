// gmail_original_cs.js - Modificar la función existente
(function(){
  const params = new URLSearchParams(location.search);
  const isOriginal = params.get("view") === "om";
  if(!isOriginal) return;
  
  function extractHeaders(){
    const pre = document.querySelector("pre");
    const bodyText = pre ? pre.textContent : document.body?.innerText || "";
    if(!bodyText) return "";
    const parts = bodyText.split(/\r?\n\r?\n/);
    const headerBlock = parts[0] || bodyText;
    return headerBlock.trim();
  }
  
  function extractCompleteEmailBody() {
    const pre = document.querySelector("pre");
    if (!pre) return "";
    
    const fullText = pre.textContent;
    const parts = fullText.split(/\r?\n\r?\n/);
    
    console.log("🔍 Buscando TODAS las partes del texto plano...");
    
    let textPlainParts = [];
    let textPlainStartIndex = -1;
    
    // Encontrar dónde empieza el text/plain
    for (let i = 0; i < parts.length; i++) {
        if (parts[i].includes('Content-Type: text/plain')) {
            textPlainStartIndex = i + 1;
            console.log(`📍 Texto plano empieza en parte ${textPlainStartIndex}`);
            break;
        }
    }
    
    if (textPlainStartIndex === -1) {
        console.log("❌ No se encontró la sección text/plain");
        return "";
    }
    
    // Recoger TODAS las partes hasta que empiece el HTML
    for (let i = textPlainStartIndex; i < parts.length; i++) {
        const part = parts[i];
        
        // Detener cuando empiece el HTML
        if (part.includes('Content-Type: text/html') || part.includes('<!DOCTYPE html>')) {
            console.log(`📍 Fin del texto plano en parte ${i} (inicio de HTML)`);
            break;
        }
        
        // Detener cuando lleguemos al final del boundary
        if (part.startsWith('--3bdaa7f7921991ae8c468d7de2c2ecc9f2272292334bf906d1abba34db01--')) {
            console.log(`📍 Fin del texto plano en parte ${i} (final del boundary)`);
            break;
        }
        
        // Solo agregar partes que tengan contenido real
        if (part.length > 5 && !part.startsWith('--3bdaa7f7921991ae8c468d7de2c2ecc9f2272292334bf906d1abba34db01')) {
            textPlainParts.push(part);
            console.log(`✅ Agregada parte ${i}: "${part.substring(0, 50)}..."`);
        }
    }
    
    console.log(`📦 Partes de texto plano encontradas: ${textPlainParts.length}`);
    
    // Unir todas las partes
    let bodyContent = textPlainParts.join('\n\n');
    
    console.log("📊 Texto plano completo:", bodyContent.length, "caracteres");
    
    // DECODIFICAR quoted-printable
    let cleanBody = bodyContent
        .replace(/=\r?\n/g, '')
        .replace(/=([0-9A-F]{2})/gi, (match, hex) => {
            return String.fromCharCode(parseInt(hex, 16));
        })
        .replace(/â/g, "'")
        .replace(/Â©/g, "©")
        .replace(/[ \t]{2,}/g, ' ')
        .replace(/\n{3,}/g, '\n\n')
        .trim();
    
    console.log("✅ CUERPO COMPLETO:", cleanBody.length, "caracteres");
    return cleanBody;
  }
  
  function injectBanner({score=0, bodyAnalysis=null}={}){
    const color = score >= 70 ? "#DC2626" : score >= 40 ? "#D97706" : "#16A34A";
    const text = score >= 70 ? "Malicioso" : score >= 40 ? "Sospechoso" : "No malicioso";
    
    if(document.getElementById("hg-banner")) return;
    
    let bodyAnalysisHTML = "";
    if (bodyAnalysis) {
      bodyAnalysisHTML = `
        <div style="margin:8px 0;padding:8px;background:#1a2333;border-radius:8px;font-size:12px">
          <div><strong>Análisis ML:</strong> ${bodyAnalysis.resultado.veredicto}</div>
          <div><strong>Probabilidad:</strong> ${bodyAnalysis.resultado.probabilidad_phishing}</div>
          <div><strong>Alertas:</strong> ${bodyAnalysis.resultado.alertas_detectadas}</div>
        </div>
      `;
    }
    
    const wrap = document.createElement("div");
    wrap.id = "hg-banner"; 
    wrap.style.all="initial"; 
    wrap.style.position="fixed"; 
    wrap.style.top="16px"; 
    wrap.style.right="16px"; 
    wrap.style.zIndex="2147483647"; 
    wrap.style.fontFamily="system-ui,Segoe UI,Roboto,Arial,sans-serif";
    
    wrap.innerHTML = `
      <div style="background:#111827;color:#E5E7EB;border-radius:14px;box-shadow:0 8px 28px rgba(0,0,0,.35);min-width:320px;max-width:400px;overflow:hidden;border:1px solid #1f2937">
        <div style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-bottom:1px solid #1f2937">
          <div style="width:10px;height:10px;border-radius:999px;background:${color}"></div>
          <div style="font-weight:700">HeaderGuard</div>
          <div style="margin-left:auto;font-weight:700;color:${color}">${text}</div>
        </div>
        <div style="padding:12px">
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
            <div style="font-size:28px;font-weight:800">${Math.round(score)}</div>
            <div style="flex:1;height:10px;background:#1f2937;border-radius:999px;overflow:hidden">
              <div style="height:100%;width:${Math.max(0,Math.min(100,score))}%;background:${color}"></div>
            </div>
          </div>
          ${bodyAnalysisHTML}
          <div style="display:flex;gap:8px">
            <button id="hg-close" style="all:unset;background:#334155;color:#E5E7EB;padding:8px 10px;border-radius:10px;text-align:center;flex:1;cursor:pointer">Cerrar</button>
            <button id="hg-more" style="all:unset;background:#2563EB;color:white;padding:8px 10px;border-radius:10px;text-align:center;flex:1;cursor:pointer">Más info</button>
          </div>
        </div>
      </div>`;
    
    document.documentElement.appendChild(wrap);
    wrap.querySelector("#hg-close").addEventListener("click", ()=> wrap.remove());
    wrap.querySelector("#hg-more").addEventListener("click", ()=> { 
      const url = chrome.runtime.getURL("report.html"); 
      window.open(url, "_blank", "noopener"); 
    });
  }

  // Extraer tanto headers como cuerpo
  const headers = extractHeaders();
  const emailBody = extractCompleteEmailBody();
  
  if(!headers) return;
  
  // Enviar ambos al background para análisis
  chrome.runtime.sendMessage({
    type: "analyzeHeaders", 
    data: headers,
    emailBody: emailBody
  }, (res)=>{ 
    if(res && res.report){ 
      injectBanner(res.report); 
    } 
  });
})();