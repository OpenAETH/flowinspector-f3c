/**
 * Flow Inspector v4 — JavaScript Runtime Proxy
 * ===============================================
 * Intercepta sin modificar el código del usuario:
 *   - funciones globales y de módulo
 *   - fetch() / XMLHttpRequest
 *   - addEventListener
 *   - Clases (métodos de prototype)
 *
 * Uso:
 *   <script src="/flow-inspector-proxy.js" data-flow-id="my-project"></script>
 *
 * O en Node.js:
 *   require('./flow-inspector-proxy');  // antes de cualquier otro require
 *
 * Configuración via data attributes o window.FLOW_CONFIG:
 *   data-flow-id    — id del flow (obligatorio)
 *   data-endpoint   — URL del backend (default: window.origin + "/flow-events/batch")
 *   data-sample     — fracción 0.0–1.0 (default: 1.0)
 */

(function () {
  "use strict";

  // ── Config ──────────────────────────────────────────────
  const scriptEl = document.currentScript;
  const CFG = Object.assign({
    flowId:    "default",
    endpoint:  (typeof location !== "undefined" ? location.origin : "") + "/flow-events/batch",
    sampleRate: 1.0,
    maxArgLen:  120,
    batchSize:  20,
    flushMs:    2000,
    enabled:    true,
  }, window.FLOW_CONFIG || {});

  if (scriptEl) {
    if (scriptEl.dataset.flowId)   CFG.flowId    = scriptEl.dataset.flowId;
    if (scriptEl.dataset.endpoint) CFG.endpoint  = scriptEl.dataset.endpoint;
    if (scriptEl.dataset.sample)   CFG.sampleRate = parseFloat(scriptEl.dataset.sample);
    if (scriptEl.dataset.disabled !== undefined) CFG.enabled = false;
  }

  if (!CFG.enabled) return;

  // ── Batch sender ────────────────────────────────────────
  let _queue = [];
  let _timer  = null;

  function _flush() {
    if (!_queue.length) return;
    const batch = _queue.splice(0);
    const body  = JSON.stringify({ events: batch });
    // Use sendBeacon for reliability when page is unloading, fetch otherwise
    if (navigator.sendBeacon && batch.length <= 5) {
      navigator.sendBeacon(CFG.endpoint, new Blob([body], { type: "application/json" }));
    } else {
      fetch(CFG.endpoint, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body,
        keepalive: true,
      }).catch(() => {});
    }
  }

  function _startTimer() {
    clearInterval(_timer);
    _timer = setInterval(_flush, CFG.flushMs);
  }

  function _push(event) {
    if (!CFG.enabled) return;
    if (CFG.sampleRate < 1.0 && Math.random() > CFG.sampleRate) return;
    _queue.push(event);
    if (_queue.length >= CFG.batchSize) _flush();
  }

  function _event(action, nodeId, payload) {
    return {
      flow_id:      CFG.flowId,
      node_id:      nodeId,
      action,
      timestamp_ms: Date.now(),
      payload,
      source:       "js",
    };
  }

  function _safeRepr(val) {
    if (val === null)      return "null";
    if (val === undefined) return "undefined";
    const t = typeof val;
    if (t === "string")   return JSON.stringify(val.slice(0, CFG.maxArgLen));
    if (t === "number" || t === "boolean") return String(val);
    if (t === "function") return `[Function ${val.name || "anonymous"}]`;
    try {
      const s = JSON.stringify(val);
      return s ? s.slice(0, CFG.maxArgLen) : String(val);
    } catch {
      return String(val).slice(0, CFG.maxArgLen);
    }
  }

  _startTimer();
  window.addEventListener("beforeunload", _flush);

  // ── Function wrapper ────────────────────────────────────
  function _wrapFn(fn, nodeId) {
    if (fn.__flowTracked) return fn;
    function wrapped(...args) {
      const argsPreview = args.slice(0, 4).map(_safeRepr).join(", ");
      _push(_event("function_call", nodeId, {
        function_name: fn.name || nodeId,
        args_preview:  argsPreview,
      }));
      const t0 = performance.now();
      try {
        const result = fn.apply(this, args);
        // Handle promises
        if (result && typeof result.then === "function") {
          return result.then(
            (res) => {
              _push(_event("function_return", nodeId, {
                function_name:  fn.name || nodeId,
                return_preview: _safeRepr(res),
                duration_ms:    parseFloat((performance.now() - t0).toFixed(2)),
                async: true,
              }));
              return res;
            },
            (err) => {
              _push(_event("exception", nodeId, {
                function_name:  fn.name || nodeId,
                exception_type: err?.name || "Error",
                message:        String(err?.message || err).slice(0, 200),
                duration_ms:    parseFloat((performance.now() - t0).toFixed(2)),
                async: true,
              }));
              throw err;
            }
          );
        }
        _push(_event("function_return", nodeId, {
          function_name:  fn.name || nodeId,
          return_preview: _safeRepr(result),
          duration_ms:    parseFloat((performance.now() - t0).toFixed(2)),
        }));
        return result;
      } catch (err) {
        _push(_event("exception", nodeId, {
          function_name:  fn.name || nodeId,
          exception_type: err?.name || "Error",
          message:        String(err?.message || err).slice(0, 200),
          duration_ms:    parseFloat((performance.now() - t0).toFixed(2)),
        }));
        throw err;
      }
    }
    wrapped.__flowTracked = true;
    wrapped.__originalFn  = fn;
    Object.defineProperty(wrapped, "name", { value: fn.name });
    return wrapped;
  }

  // ── Expose public API ───────────────────────────────────
  window.FlowInspector = {
    /**
     * Instrumenta una función explícitamente.
     *   const myWrapped = FlowInspector.track(myFunction);
     */
    track(fn, nodeId) {
      const nid = nodeId || (fn.name ? `js_fn:${fn.name}` : `js_fn:anonymous`);
      return _wrapFn(fn, nid);
    },

    /**
     * Instrumenta todos los métodos de una clase.
     *   FlowInspector.trackClass(MyClass);
     */
    trackClass(cls) {
      const proto = cls.prototype;
      Object.getOwnPropertyNames(proto).forEach((name) => {
        if (name === "constructor") return;
        const desc = Object.getOwnPropertyDescriptor(proto, name);
        if (desc && typeof desc.value === "function") {
          proto[name] = _wrapFn(desc.value, `js_cls:${cls.name}.${name}`);
        }
      });
      return cls;
    },

    /**
     * Instrumenta un objeto de módulo ES (las exports).
     *   import * as api from "./api.js";
     *   FlowInspector.trackModule(api, "api");
     */
    trackModule(moduleObj, moduleName) {
      for (const [key, val] of Object.entries(moduleObj)) {
        if (typeof val === "function") {
          moduleObj[key] = _wrapFn(val, `js_fn:${moduleName}.${key}`);
        }
      }
      return moduleObj;
    },

    /** Envía un evento custom. */
    emit(action, nodeId, payload = {}) {
      _push(_event(action, nodeId, payload));
    },

    /** Flush manual. */
    flush: _flush,

    /** Reconfigurar en runtime. */
    configure(opts = {}) {
      Object.assign(CFG, opts);
    },
  };

  // ── fetch() interceptor ─────────────────────────────────
  if (typeof window.fetch === "function") {
    const _origFetch = window.fetch.bind(window);
    window.fetch = function (input, init = {}) {
      const url    = typeof input === "string" ? input : input?.url || "";
      const method = (init.method || "GET").toUpperCase();
      // Skip our own events endpoint to avoid infinite loop
      if (url.includes("/flow-events")) return _origFetch(input, init);

      const nodeId = `fetch:${method} ${url.replace(location.origin, "").slice(0, 80)}`;
      const t0 = performance.now();
      _push(_event("fetch_call", nodeId, { url, method }));

      return _origFetch(input, init).then(
        (res) => {
          _push(_event("api_response", nodeId, {
            url,
            method,
            status_code: res.status,
            duration_ms: parseFloat((performance.now() - t0).toFixed(2)),
          }));
          return res;
        },
        (err) => {
          _push(_event("exception", nodeId, {
            url,
            method,
            exception_type: "NetworkError",
            message:        String(err?.message || err).slice(0, 200),
            duration_ms:    parseFloat((performance.now() - t0).toFixed(2)),
          }));
          throw err;
        }
      );
    };
  }

  // ── XMLHttpRequest interceptor ──────────────────────────
  const _origXHROpen = XMLHttpRequest.prototype.open;
  const _origXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._flowMethod = method;
    this._flowUrl    = url;
    return _origXHROpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (...args) {
    const url    = this._flowUrl || "";
    const method = (this._flowMethod || "GET").toUpperCase();
    if (!url.includes("/flow-events")) {
      const nodeId = `xhr:${method} ${url.replace(location.origin, "").slice(0, 80)}`;
      const t0 = performance.now();
      _push(_event("api_call", nodeId, { url, method }));
      this.addEventListener("loadend", () => {
        _push(_event("api_response", nodeId, {
          url, method,
          status_code: this.status,
          duration_ms: parseFloat((performance.now() - t0).toFixed(2)),
        }));
      });
    }
    return _origXHRSend.apply(this, args);
  };

  // ── addEventListener interceptor ────────────────────────
  const _origAEL = EventTarget.prototype.addEventListener;
  const _trackedEvents = new Set(["click","submit","change","input","keydown","keyup","scroll","resize"]);

  EventTarget.prototype.addEventListener = function (type, handler, ...opts) {
    if (_trackedEvents.has(type) && typeof handler === "function" && !handler.__flowTracked) {
      const el      = this;
      const elDesc  = el instanceof Element
        ? `${el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}${el.className ? "." + String(el.className).split(" ")[0] : ""}`
        : "window";
      const nodeId  = `event:${type} ${elDesc}`.slice(0, 100);
      const wrapped = _wrapFn(handler, nodeId);
      return _origAEL.call(this, type, wrapped, ...opts);
    }
    return _origAEL.call(this, type, handler, ...opts);
  };

  console.debug(`[FlowInspector] JS proxy active  flow=${CFG.flowId}  endpoint=${CFG.endpoint}`);
})();
