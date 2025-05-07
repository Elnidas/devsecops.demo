 DevSecOps Demo ⚙️🔒 (SAST + SCA + DAST)

---

## 0 · Panorama rápido

|Control|Herramienta|Disparo en CI| Detecta                                                            |
|---|---|---|--------------------------------------------------------------------|
|**SAST**|**Bandit**|_Commit_/_PullRequest_| Código Python inseguro (`shell=True`, hard‑coded passwords…).      |
|**SCA**|**pip‑audit**|_Commit_/_PullRequest_| CVE conocidas en dependencias (`Flask 2.0.0`, `Werkzeug 2.3.8` …). |
|**DAST**|**OWASPZAP Baseline**|_Build_ (app corriendo)| Cabeceras faltantes, XSS reflejado, redirects abiertos, etc.       |

Estos tres pasos ilustran el principio **“shift‑left”** en DevSecOps.

---

## 1 · Estructura del repositorio

```
.
├── app/
│ └── app.py          # Mini‑app Flask con vulnerabilidades intencionadas
├── requirements.txt    # Dependencias anticuadas para disparar los hallazgos
└── .github/
    └── workflows/
        └── devsecops.yml  # Pipeline CI con los 3 controles de seguridad
```

---

## 2 · La aplicación vulnerable (`app/app.py`)

```
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # ❌  Peligro:  shell=True  ➜  inyección de comandos
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
```

**Endpoints**

- `/`→ "Hello, DevSecOps" (prueba de vida).
    
- `/ping?host=<objetivo>`→ ejecuta `ping` en el sistema ⇒ perfecto para Bandit y ZAP.
    

---

## 3 · Dependencias inseguras (`requirements.txt`)

|   |   |   |
|---|---|---|
|Paquete|Versión|Motivo|
|**Flask2.0.0**|Antigua, CVE‑2021‑4396 (DoS).|
|**Werkzeug2.3.8**|Contiene 3 CVE medias.|
|**requests2.24.0**|Añade CVE de demo (proxy‑auth leak).|

Versiones _pinned_ (`==`) para reproducibilidad y hallazgos consistentes.

---

## 4 · Pipeline DevSecOps (`.github/workflows/devsecops.yml`)

```
on:
  push:
  pull_request:
  workflow_dispatch:

jobs:
  devsecops:
    runs-on: ubuntu-latest
    steps:
      - checkout ✅
      - setup‑python 3.11 ✅
      - pip install (deps + herramientas) ✅
      - bandit        # SAST  ➜ bandit.sarif
      - pip-audit     # SCA   ➜ pip-audit.cdx.json
      - gunicorn app  # levanta la app en :5000
      - ZAP baseline  # DAST  ➜ report_{html,md,json}
```

|   |   |
|---|---|
|Línea clave|¿Por qué?|
|`bandit -f sarif`|SARIF se integra con "Codescanning" de GitHub.|
|`pip-audit -f cyclonedx-json`|Produce SBOM estándar CycloneDX + CVE.|
|`artifact_name: ''` en ZAP|Desactiva upload automático (lo hacemos manual).|
|`continue-on-error: true`|Hallazgos se marcan _warning_, la demo nunca falla.|

---

## 5 · Artefactos que genera la CI

|   |   |   |   |
|---|---|---|---|
|Archivo|Quién lo genera|Formato|Contenido|
|**bandit.sarif**|Bandit|SARIF|Findings SAST (CWE, severidad, fichero/línea).|
|**pip-audit.cdx.json**|pip‑audit|CycloneDX1.4|SBOM + 11vulnerabilidades SCA.|
|**report_html.html**|ZAP|HTML|Informe navegable DAST.|
|**report_md.md**|ZAP|Markdown|Informe legible en Issues/Wiki.|
|**report_json.json**|ZAP|JSON|Datos crudos de alertas DAST.|

> Todos se suben como artefacto para descarga o se muestran en GitHubUI.

---

## 6 · Ejecutar la demo localmente

```
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app/app.py  # http://127.0.0.1:5000
# Inyección:
curl "http://127.0.0.1:5000/ping?host=example.com;ls"
```

---

## 7 · Interpretar los resultados

- **Bandit**→ `HIGH: subprocess_with_shell_equals_true` en `app.py`.
    
- **pip‑audit**→ CVEFlask, Werkzeug, Requests + SBOM.
    
- **ZAP**→ 6WARN (CSP, X‑Frame‑Options, etc.) explicado en el HTML.
    

Usa los informes como _storyboard_ de la exposición.

---

## 8 · Ideas para extender la demo

|   |   |
|---|---|
|Extra|Integración|
|**IAST**|SnykCode, ContrastScout.|
|**RASP**|AppSensor o ModSecurity con CRS.|
|**WAF+SIEM**|Enviar logs de ZAP a Elastic SIEM / Splunk.|

---

## 9·Créditos

Código bajo **MIT**. Herramientas:

- Bandit, pip‑audit, OWASP ZAP ⇒ Apache‑2.0.