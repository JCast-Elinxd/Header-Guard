// body_analyzer.js — análisis de cuerpo + llamada a API vía background

console.log("📩 HeaderGuard body analyzer cargado");

/**
 * Obtiene el texto bruto que muestra Gmail en "Mostrar original".
 * Normalmente está dentro de un <pre>.
 */
function getRawOriginalSource() {
  const pre = document.querySelector("pre");
  if (!pre) return null;
  return pre.textContent || pre.innerText || "";
}

/**
 * Extrae una parte MIME de tipo text/plain o text/html.
 * Intenta capturar el bloque desde el Content-Type hasta el siguiente boundary.
 */
// Decodifica base64 → UTF-8 de forma segura
function decodeBase64Utf8(b64) {
  try {
    const cleaned = (b64 || "").replace(/\s+/g, ""); // quitar saltos/espacios
    const bin = atob(cleaned);
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  } catch (e) {
    console.warn("[HeaderGuard body] Error decodificando base64, uso texto crudo:", e);
    return b64;
  }
}

/**
 * Extrae una parte MIME de tipo text/plain o text/html.
 * Si encuentra `Content-Transfer-Encoding: base64`, la decodifica.
 */
function extractMimePart(raw, mimeType) {
  if (!raw) return null;
  const typeEscaped = mimeType.replace("/", "\\/");

  // m[1] = bloque de headers de esa parte
  // m[2] = cuerpo tal cual (posiblemente base64)
  const re = new RegExp(
    "Content-Type:\\s*" +
      typeEscaped +
      "[^\\r\\n]*" +
      "([\\s\\S]*?)" +              // headers adicionales (incluye Content-Transfer-Encoding)
      "\\r?\\n\\r?\\n" +
      "([\\s\\S]*?)(?:" +           // cuerpo
      "\\r?\\n--[A-Za-z0-9'()+_.,\\/:=? -]+|$)", // hasta el siguiente boundary o fin
    "i"
  );

  const m = re.exec(raw);
  if (!m) return null;

  const headerBlock = m[1] || "";
  let body = m[2] || "";

  const encMatch = headerBlock.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
  const encoding = encMatch ? encMatch[1].trim().toLowerCase() : null;

  if (encoding === "base64") {
    body = decodeBase64Utf8(body);
  }

  return body;
}


/**
 * Elimina etiquetas HTML y bloques de <style>/<script>.
 */
function stripHtml(html) {
  if (!html) return "";
  let text = html
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<\/?[^>]+>/g, " ");
  text = text.replace(/\s+/g, " ").trim();
  return text;
}

/**
 * Limpia saltos de línea, espacios extra y ruido básico.
 */
function basicCleanup(text) {
  if (!text) return "";
  return text
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\s+$/gm, "")
    .trim();
}

/**
 * Extrae el cuerpo del mensaje de la fuente cruda de "Mostrar original".
 *  - Primero busca text/plain
 *  - Si no hay, intenta text/html y le quita etiquetas
 *  - Si falla, como fallback toma lo que haya tras el primer doble salto de línea
 */
function extractCleanBodyFromOriginal(raw) {
  if (!raw) return "";

  // 1) Intentar text/plain
  const plainPart = extractMimePart(raw, "text/plain");
  if (plainPart) {
    return basicCleanup(plainPart);
  }

  // 2) Fallback: text/html -> strip tags
  const htmlPart = extractMimePart(raw, "text/html");
  if (htmlPart) {
    const stripped = stripHtml(htmlPart);
    return basicCleanup(stripped);
  }

  // 3) Último recurso: todo lo que haya tras el primer doble salto de línea
  const sepMatch = raw.match(/\r?\n\r?\n/);
  if (!sepMatch) {
    return basicCleanup(raw);
  }
  const idx = raw.indexOf(sepMatch[0]);
  const body = raw.slice(idx + sepMatch[0].length);
  return basicCleanup(body);
}

/**
 * Envia el texto limpio al background para que él llame a la API HTTP.
 */
function sendBodyToBackground(cleanText) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { type: "analyzeBody", text: cleanText },
      (resp) => {
        if (chrome.runtime.lastError) {
          return reject(chrome.runtime.lastError);
        }
        resolve(resp);
      }
    );
  });
}

/**
 * Actualiza el banner existente (#hg-banner) con el nuevo score combinado.
 */
function updateBannerWithReport(report) {
  if (!report) return;
  const wrap = document.getElementById("hg-banner");
  if (!wrap) return;

  const score = Math.max(0, Math.min(100, report.score ?? 0));
  const headerScore = report.headerScore ?? null;
  const contentScore = report.contentScore ?? null;

  const color = score >= 70 ? "#DC2626" : score >= 40 ? "#D97706" : "#16A34A";
  const text = score >= 70 ? "Malicioso" : score >= 40 ? "Sospechoso" : "No malicioso";

  // círculo
  const dot = wrap.querySelector("div[style*='width:10px'][style*='height:10px']");
  if (dot) dot.style.background = color;

  // etiqueta de texto (Malicioso / Sospechoso / No malicioso)
  const label = wrap.querySelector("div[style*='margin-left:auto']");
  if (label) {
    label.textContent = text;
    label.style.color = color;
  }

  // número grande
  const num = wrap.querySelector("div[style*='font-size:28px']");
  if (num) num.textContent = String(Math.round(score));

  // barra de progreso
  const bar = wrap.querySelector("div[style*='height:100%;width']");
  if (bar) {
    bar.style.width = `${score}%`;
    bar.style.background = color;
  }

  // Opcional: log para debug
  console.log("[HeaderGuard body] Banner actualizado con score combinado:", {
    score,
    headerScore,
    contentScore
  });
}

/**
 * Función principal:
 *  - Detecta que estamos en "Mostrar original" (view=om)
 *  - Extrae texto limpio
 *  - Pide al background que llame a la API
 *  - Imprime en consola el texto enviado y el resultado
 *  - Actualiza el banner con el score combinado
 */
export async function analyzeOriginalBodyAndLog() {
  try {
    // Aseguramos que estamos en la vista de "Mostrar original"
    if (!/view=om/.test(location.search)) {
      console.debug("[HeaderGuard body] No es vista 'Mostrar original', no se hace nada.");
      return;
    }

    const raw = getRawOriginalSource();
    if (!raw) {
      console.warn("[HeaderGuard body] No encontré el <pre> con el mensaje original.");
      return;
    }

    const cleanText = extractCleanBodyFromOriginal(raw);
    if (!cleanText) {
      console.warn("[HeaderGuard body] No se pudo extraer texto limpio del cuerpo.");
      return;
    }

    console.log(
      "[HeaderGuard body] Texto limpio extraído (primeros 500 caracteres):",
      cleanText.slice(0, 500)
    );

    // Enviar texto al background → éste llama a la API HTTP
    const resp = await sendBodyToBackground(cleanText);

    if (!resp || !resp.ok) {
      console.error("[HeaderGuard body] Error desde background/analyzeBody:", resp?.error);
      return;
    }

    console.log("[HeaderGuard body] Resultado API /analyze:", resp.data);
    console.log("[HeaderGuard body] Texto enviado completo:", cleanText);

    // 🆕 Actualiza el banner con el score combinado
    if (resp.combinedReport) {
      updateBannerWithReport(resp.combinedReport);
    }
  } catch (e) {
    console.error("[HeaderGuard body] Error en analyzeOriginalBodyAndLog:", e);
  }
}
