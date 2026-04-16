# Flow Inspector v3.0 — Python & Web Repository Analyzer

> Analiza estructura, dependencias, call graph y dead code de proyectos **Python, HTML, CSS y JavaScript**. Deploy en Render.com con un solo archivo `render.yaml`.

---

## 🚀 Deploy en Render.com

1. Push este repositorio a GitHub/GitLab
2. En [Render.com](https://render.com) → New Web Service → conectar repo
3. Render detecta `render.yaml` automáticamente
4. Configurar `ACCESS_KEY` en Environment Variables (opcional)
5. ¡Listo!

---

## 🔐 Login / Acceso

Si configurás `ACCESS_KEY` en las env vars, la app mostrará una pantalla de login antes de permitir el acceso. Si la variable está vacía, la app es de acceso libre (útil para dev local).

---

## 📁 Estructura del proyecto

```
FlowInspector/
├── Backend/
│   └── app.py          ← API FastAPI (Python + Web analysis)
├── Frontend/
│   ├── index.html      ← App principal
│   └── landing.html    ← Landing page
├── requirements.txt
├── render.yaml         ← Config de deploy
├── .env.example        ← Variables de entorno ejemplo
└── README.md
```

---

## 🔌 API Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET`  | `/health` | Health check |
| `POST` | `/api/login` | Verificar clave de acceso |
| `GET`  | `/api/auth-required` | ¿Login requerido? |
| `POST` | `/analyze/dump` | Analiza dump de texto Python |
| `POST` | `/analyze/upload` | Sube archivos `.py` |
| `POST` | `/analyze/zip` | Sube `.zip` con archivos `.py` |
| `POST` | `/analyze/web-upload` | Sube archivos `.html/.css/.js` |
| `POST` | `/analyze/web-zip` | Sube `.zip` con proyecto web |
| `POST` | `/analyze/web-dump` | Analiza dump de proyecto web |
| `POST` | `/traceability` | Trazabilidad de un archivo |
| `POST` | `/api/groq` | Proxy Groq para Change Impact AI |

---

## 🌐 Análisis Web — Qué detecta

### HTML
- Scripts externos, stylesheets, links entre páginas
- IDs y clases usadas, Web Components, formularios

### CSS
- Selectores (class, ID, element), variables CSS (`--custom-props`)
- @imports, media queries, keyframes
- Cross-ref: qué selectores coinciden con clases/IDs del HTML

### JavaScript
- Declaraciones de funciones y clases, imports (ES modules + require)
- Event listeners, DOM queries, fetch calls, endpoints de API

---

## 🐍 Análisis Python (v2.1 original)

- Grafo interactivo con force layout
- Dead Code Detector con score graduado 0-100%
- Trazabilidad upstream/downstream
- Change Impact con Groq AI

---

## ⚙️ Variables de entorno

Ver `.env.example` para la lista completa.

```bash
ACCESS_KEY=tu_clave_secreta   # Protege el acceso a la app
PORT=10000                    # Puerto (Render lo asigna)
```

---

## 📱 Responsive Design

- **Desktop** (≥1024px): Layout completo con sidebar, grafo y panel de detalle
- **Tablet** (768-1023px): Layout adaptado, paneles más angostos
- **Mobile** (<768px): Sidebar como drawer, panel de detalle como bottom sheet

---

## 🏗️ Arquitectura (Backend)

```
Backend/app.py
├── Auth              → Login via ACCESS_KEY env var
├── RepositoryLoader  → Parseo de dumps Python
├── ASTParser         → Análisis estático Python (módulo ast)
├── FileDependencyAnalyzer
├── StructureAnalyzer
├── CallGraphAnalyzer
├── DependencyGraphBuilder
├── DeadCodeAnalyzer  → Score 0.0–1.0 con exenciones
├── TraceabilityAnalyzer
├── WebFileParser     → Parser HTML/CSS/JS con regex
├── WebDependencyGraphBuilder → Grafo web
└── TraceabilityAnalyzer
```

---

build with 🧡 by [AETHERYON Systems](https://aetheryon.com)
