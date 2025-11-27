// gmail_original_cs.js - Versión completamente nueva y robusta
(function(){
  const params = new URLSearchParams(location.search);
  const isOriginal = params.get("view") === "om";
  if(!isOriginal) return;
  
  console.log("🚀 HeaderGuard iniciado - Extracción mejorada");
  
  // Función para decodificar contenido
  function decodeContent(content, encoding, contentType = '') {
    if (!content || !encoding) return content || '';
    
    const cleanContent = content.replace(/\s/g, '');
    if (cleanContent.length === 0) return '';
    
    try {
      if (encoding.toLowerCase().includes('base64')) {
        console.log("🔓 Decodificando base64...");
        return atob(cleanContent);
      } else if (encoding.toLowerCase().includes('quoted-printable')) {
        console.log("🔓 Decodificando quoted-printable...");
        return content
          .replace(/=\r?\n/g, '')
          .replace(/=([0-9A-F]{2})/gi, (match, hex) => {
            return String.fromCharCode(parseInt(hex, 16));
          })
          .replace(/â/g, "'")
          .replace(/Â©/g, "©")
          .replace(/=/g, '');
      }
    } catch (error) {
      console.log('❌ Error decodificando contenido:', error);
    }
    
    return content;
  }

  // Extraer headers básicos
  function extractHeaders(){
    const pre = document.querySelector("pre");
    const bodyText = pre ? pre.textContent : document.body?.innerText || "";
    if(!bodyText) return "";
    const parts = bodyText.split(/\r?\n\r?\n/);
    const headerBlock = parts[0] || bodyText;
    return headerBlock.trim();
  }

  // Extraer contenido de attachments RFC822
  function extractFromRFC822Attachments(parts) {
    console.log("📎 Buscando en attachments RFC822...");
    let inRFC822 = false;
    let rfc822Content = [];
    let currentEncoding = '';
    
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      
      // Detectar inicio de attachment message/rfc822
      if (part.includes('Content-Type: message/rfc822')) {
        inRFC822 = true;
        console.log("📍 Encontrado attachment message/rfc822");
        continue;
      }
      
      // Si estamos en un attachment RFC822
      if (inRFC822) {
        // Capturar encoding
        if (part.includes('Content-Transfer-Encoding:')) {
          const encodingMatch = part.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
          if (encodingMatch) currentEncoding = encodingMatch[1].trim();
        }
        
        // Buscar text/plain dentro del attachment
        if (part.includes('Content-Type: text/plain')) {
          console.log("📍 Encontrado text/plain dentro de RFC822");
          if (i + 1 < parts.length) {
            const contentPart = parts[i + 1];
            if (!contentPart.includes('Content-Type:') && 
                !contentPart.includes('Content-Transfer-Encoding:') &&
                contentPart.length > 5) {
              
              const decoded = decodeContent(contentPart, currentEncoding || 'quoted-printable');
              if (decoded && decoded.trim().length > 10) {
                rfc822Content.push(decoded);
                console.log("✅ Contenido extraído de RFC822");
              }
            }
          }
        }
        
        // Buscar text/html también
        if (part.includes('Content-Type: text/html')) {
          console.log("📍 Encontrado text/html dentro de RFC822");
          if (i + 1 < parts.length) {
            const contentPart = parts[i + 1];
            if (!contentPart.includes('Content-Type:') && 
                !contentPart.includes('Content-Transfer-Encoding:') &&
                contentPart.length > 5) {
              
              const decoded = decodeContent(contentPart, currentEncoding || 'quoted-printable');
              if (decoded && decoded.trim().length > 10) {
                // Extraer texto del HTML
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = decoded;
                const textContent = tempDiv.textContent || tempDiv.innerText || '';
                if (textContent.length > 10) {
                  rfc822Content.push(textContent);
                  console.log("✅ Texto extraído de HTML en RFC822");
                }
              }
            }
          }
        }
        
        // Salir del attachment cuando encontremos el boundary de cierre
        if (part.includes('--_004_') && part.endsWith('--')) {
          inRFC822 = false;
          break;
        }
      }
    }
    
    return rfc822Content.length > 0 ? rfc822Content.join('\n\n') : null;
  }

  // Extraer cualquier text/plain disponible
  function extractAnyTextPlain(parts) {
    console.log("🔍 Buscando cualquier text/plain disponible...");
    let textContent = [];
    let inTextPlain = false;
    let currentEncoding = '';
    
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      
      // Capturar encoding
      if (part.includes('Content-Transfer-Encoding:')) {
        const encodingMatch = part.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
        if (encodingMatch) currentEncoding = encodingMatch[1].trim();
      }
      
      if (part.includes('Content-Type: text/plain')) {
        inTextPlain = true;
        console.log(`📍 Texto plano encontrado en parte ${i}, encoding: ${currentEncoding}`);
        continue;
      }
      
      if (inTextPlain) {
        // Si encontramos el siguiente header, salir
        if (part.includes('Content-Type:') || part.includes('--_')) {
          inTextPlain = false;
          currentEncoding = '';
          continue;
        }
        
        // Solo agregar si tiene contenido real y no es otro header
        if (part.length > 5 && 
            !part.includes('Content-Type:') && 
            !part.includes('Content-Transfer-Encoding:')) {
          
          const decodedContent = decodeContent(part, currentEncoding);
          if (decodedContent && decodedContent.trim().length > 5) {
            textContent.push(decodedContent);
            console.log(`✅ Contenido text/plain agregado: ${decodedContent.length} chars`);
          }
        }
      }
      
      // Resetear encoding cuando cambiemos de sección
      if (part.includes('--_')) {
        currentEncoding = '';
      }
    }
    
    return textContent.length > 0 ? textContent.join('\n\n') : null;
  }

  // Extraer contenido de text/html
  function extractFromHTML(parts) {
    console.log("🔍 Buscando contenido HTML...");
    let htmlContent = [];
    let inHTML = false;
    let currentEncoding = '';
    
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      
      if (part.includes('Content-Transfer-Encoding:')) {
        const encodingMatch = part.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
        if (encodingMatch) currentEncoding = encodingMatch[1].trim();
      }
      
      if (part.includes('Content-Type: text/html')) {
        inHTML = true;
        console.log(`📍 HTML encontrado en parte ${i}, encoding: ${currentEncoding}`);
        continue;
      }
      
      if (inHTML) {
        if (part.includes('Content-Type:') || part.includes('--_')) {
          inHTML = false;
          currentEncoding = '';
          continue;
        }
        
        if (part.length > 10 && 
            !part.includes('Content-Type:') && 
            !part.includes('Content-Transfer-Encoding:')) {
          
          const decodedContent = decodeContent(part, currentEncoding);
          if (decodedContent && decodedContent.trim().length > 10) {
            // Convertir HTML a texto
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = decodedContent;
            const textContent = tempDiv.textContent || tempDiv.innerText || '';
            if (textContent.length > 10) {
              htmlContent.push(textContent);
              console.log(`✅ Texto extraído de HTML: ${textContent.length} chars`);
            }
          }
        }
      }
    }
    
    return htmlContent.length > 0 ? htmlContent.join('\n\n') : null;
  }

  // Función principal mejorada
  function extractCompleteEmailBody() {
    const pre = document.querySelector("pre");
    if (!pre) {
      console.log("❌ No se encontró elemento pre");
      return "";
    }
    
    const fullText = pre.textContent;
    const parts = fullText.split(/\r?\n\r?\n/);
    
    console.log(`📧 Partes totales del email: ${parts.length}`);
    
    // Estrategia 1: Buscar text/plain normal
    let bodyContent = extractAnyTextPlain(parts);
    
    // Estrategia 2: Buscar en attachments RFC822
    if (!bodyContent || bodyContent.trim().length < 10) {
      bodyContent = extractFromRFC822Attachments(parts);
    }
    
    // Estrategia 3: Buscar en HTML
    if (!bodyContent || bodyContent.trim().length < 10) {
      bodyContent = extractFromHTML(parts);
    }
    
    // Estrategia 4: Fallback - usar texto después de headers
    if (!bodyContent || bodyContent.trim().length < 10) {
      console.log("🔍 Usando fallback - texto después de headers");
      const headerEnd = fullText.indexOf('\n\n');
      if (headerEnd !== -1) {
        const potentialBody = fullText.substring(headerEnd + 2);
        // Limpiar y verificar si es contenido válido
        const cleanBody = potentialBody
          .replace(/Content-Type:.*?\n/g, '')
          .replace(/Content-Transfer-Encoding:.*?\n/g, '')
          .replace(/--_.*?\n/g, '')
          .trim();
        
        if (cleanBody.length > 20 && !cleanBody.includes('Received:') && !cleanBody.includes('Message-ID:')) {
          bodyContent = cleanBody;
          console.log("✅ Contenido encontrado via fallback");
        }
      }
    }
    
    const finalContent = bodyContent ? bodyContent.trim() : '';
    console.log(`📊 CUERPO EXTRAÍDO: ${finalContent.length} caracteres`);
    
    if (finalContent.length > 0) {
      console.log("👀 Preview:", finalContent.substring(0, 200) + "...");
    } else {
      console.log("❌ NO se pudo extraer contenido del cuerpo");
    }
    
    return finalContent;
  }

  // Banner de resultados (existente)
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

  // Ejecutar extracción
  const headers = extractHeaders();
  const emailBody = extractCompleteEmailBody();
  
  if(!headers) {
    console.log("❌ No se pudieron extraer headers");
    return;
  }
  
  console.log(`📨 Headers: ${headers.length} caracteres`);
  console.log(`📧 Cuerpo: ${emailBody ? emailBody.length + ' caracteres' : 'VACÍO'}`);
  
  // Enviar para análisis
  chrome.runtime.sendMessage({
    type: "analyzeHeaders", 
    data: headers,
    emailBody: emailBody
  }, (res)=>{ 
    if(res && res.report){ 
      console.log("✅ Análisis completado, inyectando banner");
      injectBanner(res.report); 
    } else {
      console.log("❌ No se recibió reporte del análisis");
    }
  });
})();