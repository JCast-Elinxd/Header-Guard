from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from urllib.parse import urlparse, parse_qs, unquote


app = FastAPI(title="HeaderGuard ML API", version="3.0 (Hybrid Detection)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_A_TEXT = "poseidon07x/bert-base-multilingual-cased-spam-mail-detection" 
MODEL_B_TEXT = "asfilcnx3/spam-detection-es"
MODEL_C_URL = "Eason918/malicious-url-detector-v2"

MEMORY_ARGS = {"torch_dtype": torch.float16} 

# Pesos para la IA
W_A = 0.40
W_B = 0.50 
W_C = 0.10

models = {
    "text_A": None, "tokenizer_A": None,
    "text_B": None, "tokenizer_B": None,
    "url_C": None, "tokenizer_C": None
}

acortadores = [a.lower() for a in [
"ln.run/", "n9.cl/","acortar.link/","ckpn.io/","surl.li/","bit.ly/","tinyurl.com/","t.co/","cutt.ly/",
"is.gd/","rebrand.ly/","ow.ly/","goo.su/","tiny.cc/","bit.do/","rb.gy/","t.ly/","buff.ly/","v.gd/","gg.gg/",
"shrtco.de/","cli.re/","s.id/","soo.gd/","mcaf.ee/","amzn.to/","apple.co/","fb.me/",
"lnkd.in/","qr.ae/","adf.ly/","shorte.st/","u.to/","grabify.link/","iplogger.org/","iplogger.com/","2no.co/",
"bmw.zone/","ouo.io/","cutt.us/","tny.im/","clk.sh/","t2m.io/","yourls.org/","po.st/","bl.ink/",
"lc.chat/","shorturl.at/", "shortest.link/","tiny.one/","shrt.link/","shre.ink/","chilp.it/","short.cm/","lnks.co/","urlzs.com/","short.io/","linklyhq.com/","tny.sh/","shorturllink.com/","hyp.is/"
]]

urgencia = [u.lower() for u in [
    "inmediato", "ahora mismo", "pronto", "urgente", "de inmediato",
    "antes de", "a la brevedad", "fecha límite", "expira", "caduca",
    "requiere acción", "proceda", "ejecutar", "actúe", "se necesita",
    "confirmar", "verificar", "validar", "restablecer", "actualizar",
    "última oportunidad", "solo quedan", "solo por 24 horas", "se agota",
    "por tiempo limitado", "último aviso", "finaliza", "pendiente",
    "fallida", "no procesada", "en breve", "si no lo hace",
    "automáticamente", "a partir de", "proceso de cierre", "eliminación",
    "desactivación", "suspensión", "bloqueo", "deshabilitado"
]]

amenaza = [a.lower() for a in [
    "bloqueada","bloquear","inhabilitada","restringida","suspendida","cerrada",
    "cancelada","desactivada","inaccesible","limitada","cerrará","matar","orden judicial",
    "proceso legal","penalización","sanción","multa","judicial","sabemos lo que hiciste",
    "sabemos lo que hizo","encarcelado","demanda","incumplimiento","regulación","fraude","ilegal",
    "cargo extra","deuda","intereses","cobro","pérdidas","retención","impago","saldo negativo",
    "adeudo","recargo","riesgo","amenaza","violación de seguridad","comprometida",
    "advertencia","alerta crítica","intento no autorizado","actividad sospechosa",
    "detección de malware","vulnerabilidad"
]]

sex = [s.lower() for s in ["vagina","pene","semen","perra","puta","mándame una foto"]]


@app.on_event("startup")
def cargar_modelos():
    print("CARGANDO MODELOS...")
    try:
        models["tokenizer_A"] = AutoTokenizer.from_pretrained(MODEL_A_TEXT)
        models["text_A"] = AutoModelForSequenceClassification.from_pretrained(MODEL_A_TEXT, **MEMORY_ARGS)
        
        models["tokenizer_B"] = AutoTokenizer.from_pretrained(MODEL_B_TEXT)
        models["text_B"] = AutoModelForSequenceClassification.from_pretrained(MODEL_B_TEXT, **MEMORY_ARGS)
        
        models["tokenizer_C"] = AutoTokenizer.from_pretrained(MODEL_C_URL)
        models["url_C"] = AutoModelForSequenceClassification.from_pretrained(MODEL_C_URL, **MEMORY_ARGS)
        print("LISTO...")
    except Exception as e:
        print(f"FATAL: {e}")
        raise e

def predict(model_key, tokenizer_key, text) -> list:
    if not models[model_key]: return [0.5, 0.5] # Fallback seguro
    inputs = models[tokenizer_key](text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = models[model_key](**inputs)
        return torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()

#FUNCIONES
def separar(email):#SEPARA EL LOS LINKS DEL RESTO DEL TEXTO DEL CORREO
    pattern = re.compile(r'(?:https?:\/\/|www\.)\S+', re.IGNORECASE) #Esta es la expresión regular para encontrar los links
    links = [] #Pueden haber varios, hay que tener una lista.
    def _repl(m):
        token = m.group(0)
        clean = token.rstrip('.,;:!?)"\']')
        links.append(clean)
        trailing = token[len(clean):]
        return 'link' + trailing
    new_text = pattern.sub(_repl, email)
    return new_text, links

#Revisa si la dirección real esta oculta en un enlace mas largo
def revisar_link(link, resultados):
    try:
        params = ['q', 'u', 'redirect', 'target']
        parsed = urlparse(link)
        
        # Revisar Query
        qs = parse_qs(parsed.query)
        for p in params:
            if p in qs and qs[p]:
                decoded = unquote(qs[p][0])
                msg = f"Redirección oculta detectada hacia: {decoded}"
                if msg not in resultados: resultados.append(msg)
                return decoded
        
        frag = parse_qs(parsed.fragment)
        for p in params:
            if p in frag and frag[p]:
                decoded = unquote(frag[p][0])
                msg = f"Redirección en fragmento detectada hacia: {decoded}"
                if msg not in resultados: resultados.append(msg)
                return decoded
    except Exception:
        pass
    return link

def revisar_acortadores(link, resultados):
    lower = link.lower()
    for ac in acortadores:
        if ac in lower:
            msg = f"Uso de acortador de enlaces detectado ({ac})"
            if msg not in resultados: resultados.append(msg)
            return True
    return False

def revision_preliminar_texto(texto, resultados):
    low = texto.lower()
    found_threat = False
    found_urgency = False
    found_sex = False

    for phrase in amenaza:
        if phrase in low:
            found_threat = True
            break
    for phrase in urgencia:
        if phrase in low:
            found_urgency = True
            break
    for phrase in sex:
        if phrase in low:
            found_sex = True
            break
            
    if found_threat: resultados.append("Contiene lenguaje amenazante")
    if found_urgency: resultados.append("Contiene palabras de urgencia")
    if found_sex: resultados.append("Se detecto contenido sexual o explícito")

class EmailRequest(BaseModel):
    text: str

@app.post("/analyze")
async def analyze_email(request: EmailRequest):
    email_texto = request.text
    
    alertas_heuristicas = []

    revision_preliminar_texto(email_texto, alertas_heuristicas)
    
    texto_limpio, links = separar(email_texto)

    urls_info = []
    risk_C = 0.0
    
    if links:
        max_link_risk = 0.0
        for url in links:
            real_url = revisar_link(url, alertas_heuristicas)
            
            es_acortador = revisar_acortadores(real_url, alertas_heuristicas)
            
            scores_C = predict("url_C", "tokenizer_C", real_url)
            current_risk = sum(scores_C[1:]) # Suma de clases maliciosas
            
            if es_acortador: current_risk = min(1.0, current_risk + 0.1)

            if current_risk > max_link_risk: max_link_risk = current_risk

            urls_info.append({
                "url": url,
                "url_analizada": real_url,
                "riesgo_ia": f"{current_risk:.2%}",
                "es_acortador": es_acortador
            })
        risk_C = max_link_risk
    

    scores_A = predict("text_A", "tokenizer_A", texto_limpio)
    risk_A = scores_A[1]
    
    scores_B = predict("text_B", "tokenizer_B", texto_limpio)
    risk_B = scores_B[1]

    if links:
        weighted_avg = (risk_A * W_A) + (risk_B * W_B) + (risk_C * W_C)
    else:
        norm_A = W_A / (W_A + W_B)
        norm_B = W_B / (W_A + W_B)
        weighted_avg = (risk_A * norm_A) + (risk_B * norm_B)


    factor_ajuste = 1.0
    
    tiene_sexo = "Se detecto contenido sexual o explícito" in alertas_heuristicas
    tiene_amenaza = "Contiene lenguaje amenazante" in alertas_heuristicas
    tiene_urgencia = "Contiene palabras de urgencia" in alertas_heuristicas
    

    if tiene_sexo:
        factor_ajuste = 1.70
    elif tiene_amenaza:
        factor_ajuste = 1.30
    elif tiene_urgencia:
        factor_ajuste = 1.15
        
    
    final_score = weighted_avg
    

    high_risk_count = sum([1 for r in [risk_A, risk_B, risk_C] if r > 0.8])

    if high_risk_count >= 2:
        final_score = (weighted_avg + max(risk_A, risk_B, risk_C)) / 2

    final_score = min(1.0, final_score * factor_ajuste)

    if final_score > 0.80: veredicto = "PELIGRO CRITICO"
    elif final_score > 0.60: veredicto = "ALTO RIESGO"
    elif final_score > 0.30: veredicto = "SOSPECHOSO"
    else: veredicto = "SEGURO"

    return {
        "resultado": {
            "veredicto": veredicto,
            "probabilidad_phishing": f"{final_score:.2%}",
            "alertas_detectadas": len(alertas_heuristicas)
        },
        "analisis_heuristico": {
            "alertas": alertas_heuristicas,
            "detalle_urls": urls_info
        },
        "analisis_ia": {
            "modelo_multilingue": f"{risk_A:.2%}",
            "modelo_espanol": f"{risk_B:.2%}",
            "modelo_urls": f"{risk_C:.2%}"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)