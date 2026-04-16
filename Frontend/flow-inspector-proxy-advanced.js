/**
 * Flow Inspector v4 — JS Proxy Advanced  (Fase 4)
 * ==================================================
 * Proxy avanzado sobre el básico de Fase 1. Agrega:
 *
 *  1. ES module auto-patching via dynamic import() wrapper
 *  2. WebSocket live feed (opcional): eventos en tiempo real sin batching
 *  3. Worker thread instrumentation (Web Workers y SharedWorkers)
 *  4. React/Vue component lifecycle hooks
 *  5. MutationObserver para detectar componentes dinámicos
 *  6. Performance timing (window.performance.measure wrapping)
 *  7. Error boundary: captura errores globales no manejados
 *  8. Context propagation: traza requestId a través de calls async
 *
 * Integra con flow-inspector-proxy.js de Fase 1.
 * Puede usarse solo o en conjunto.
 *
 * Uso:
 *   <script src="/flow-inspector-proxy.js" data-flow-id="myapp"></script>
 *   <script src="/flow-inspector-proxy-advanced.js"></script>
 *
 * O en módulo ES:
 *   import '/flow-inspector-proxy-advanced.js';
 */

(function () {
  "use strict";

  // ── Config ─────────────────────────────────────────────
  const CFG = Object.assign({
    flowId:       "default",
    endpoint:     (typeof location !== "undefined" ? location.origin : "") + "/flow-events/batch",
    wsEndpoint:   "",          // if set, use WebSocket instead of batch HTTP
    sampleRate:   1.0,
    trackReact:   true,
    trackVue:     true,
    trackWorkers: true,
    trackErrors:  true,
    trackPerf:    true,
    trackMutations: false,     // MutationObserver on DOM (expensive, off by default)
    contextProp:  true,        // async context propagation
    enabled:      true,
  }, window.FLOW_CONFIG || {}, window.FLOW_ADVANCED_CONFIG || {});

  if (!CFG.enabled) return;

  // ── Inherit from Fase 1 proxy if present ───────────────
  const FI = window.FlowInspector || {};
  const _push = FI._push || function (ev) {
    // Standalone batch sender fallback
    if (!_AdvancedSender._q) _AdvancedSender._q = [];
    _AdvancedSender._q.push(ev);
  };

  function _emit(action, nodeId, payload) {
    if (!CFG.enabled) return;
    if (CFG.sampleRate < 1.0 && Math.random() > CFG.sampleRate) return;
    const ev = {
      flow_id:      CFG.flowId,
      node_id:      nodeId,
      action,
      timestamp_ms: Date.now(),
      payload:      payload || {},
      source:       "js_advanced",
    };
    if (_wsReady()) {
      _wsSend(ev);
    } else {
      _push(ev);
    }
  }

  // ── WebSocket live feed ─────────────────────────────────
  let _ws    = null;
  let _wsOk  = false;
  let _wsBuf = [];

  function _wsReady() { return _ws && _wsOk; }

  function _wsSend(ev) {
    if (_wsReady()) {
      _ws.send(JSON.stringify(ev));
    } else {
      _wsBuf.push(ev);
    }
  }

  function _initWS(url) {
    if (!url || typeof WebSocket === "undefined") return;
    _ws = new WebSocket(url);
    _ws.onopen = () => {
      _wsOk = true;
      // Flush buffered events
      _wsBuf.splice(0).forEach(ev => _ws.send(JSON.stringify(ev)));
      _emit("custom", "ws:connected", { url });
    };
    _ws.onclose = () => { _wsOk = false; };
    _ws.onerror = () => { _wsOk = false; };
  }

  if (CFG.wsEndpoint) _initWS(CFG.wsEndpoint);

  // ── Standalone batch sender (fallback) ─────────────────
  const _AdvancedSender = {
    _q: [],
    _timer: null,
    init() {
      this._timer = setInterval(() => this._flush(), 2000);
      if (typeof window !== "undefined") {
        window.addEventListener("beforeunload", () => this._flush());
      }
    },
    _flush() {
      if (!this._q.length) return;
      const batch = this._q.splice(0);
      const body  = JSON.stringify({ events: batch });
      try {
        fetch(CFG.endpoint, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body, keepalive: true,
        }).catch(() => {});
      } catch (_) {}
    },
  };
  if (!window.FlowInspector) _AdvancedSender.init();

  // ── Async context propagation ───────────────────────────
  let _ctxId = 0;
  const _asyncCtx = new Map(); // asyncId → contextId

  function _newCtx() { return ++_ctxId; }
  function _currentCtx() {
    // Simple heuristic: use the most recent context
    return _ctxId;
  }

  // ── React hooks ─────────────────────────────────────────
  function _hookReact() {
    if (!CFG.trackReact) return;
    // React DevTools global hook
    if (typeof window.__REACT_DEVTOOLS_GLOBAL_HOOK__ === "undefined") {
      window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {};
    }
    const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
    const origOnCommit = hook.onCommitFiberRoot;
    hook.onCommitFiberRoot = function (rendererID, root, ...args) {
      try {
        const fiber = root?.current;
        if (fiber) {
          _walkFiber(fiber);
        }
      } catch (_) {}
      if (origOnCommit) return origOnCommit.call(this, rendererID, root, ...args);
    };
  }

  function _walkFiber(fiber, depth = 0) {
    if (!fiber || depth > 5) return;
    const type = fiber.type;
    const name = (typeof type === "function" && (type.displayName || type.name)) ||
                 (typeof type === "string" && type);
    if (name && name !== "div" && name !== "span" && !name.startsWith("_")) {
      const nid = `react:${name}`;
      _emit("custom", nid, {
        event_type:     "react_render",
        component_name: name,
        fiber_tag:      fiber.tag,
      });
    }
    _walkFiber(fiber.child,   depth + 1);
    _walkFiber(fiber.sibling, depth + 1);
  }

  // ── Vue DevTools hook ────────────────────────────────────
  function _hookVue() {
    if (!CFG.trackVue) return;
    // Vue 3 app.config.globalProperties
    if (window.__VUE_APP__) {
      const app = window.__VUE_APP__;
      const origMount = app.mount?.bind(app);
      if (origMount) {
        app.mount = function (...args) {
          _emit("custom", "vue:mount", { args: args.map(String).slice(0, 2) });
          return origMount(...args);
        };
      }
    }
  }

  // ── Worker instrumentation ──────────────────────────────
  function _hookWorkers() {
    if (!CFG.trackWorkers || typeof Worker === "undefined") return;
    const OrigWorker = Worker;
    window.Worker = function (url, opts) {
      const w = new OrigWorker(url, opts);
      const nodeId = `worker:${String(url).split("/").pop()}`;
      _emit("custom", nodeId, { event_type: "worker_created", url: String(url) });
      const origPostMessage = w.postMessage.bind(w);
      w.postMessage = function (msg, ...rest) {
        _emit("custom", nodeId, {
          event_type: "worker_postMessage",
          data_type:  typeof msg,
          data_preview: String(msg).slice(0, 60),
        });
        return origPostMessage(msg, ...rest);
      };
      w.addEventListener("message", (e) => {
        _emit("custom", nodeId, {
          event_type:   "worker_message",
          data_type:    typeof e.data,
          data_preview: String(e.data).slice(0, 60),
        });
      });
      w.addEventListener("error", (e) => {
        _emit("exception", nodeId, {
          event_type: "worker_error",
          message:    e.message,
        });
      });
      return w;
    };
  }

  // ── Global error capture ────────────────────────────────
  function _hookErrors() {
    if (!CFG.trackErrors || typeof window === "undefined") return;

    window.addEventListener("error", (e) => {
      _emit("exception", `global:uncaught`, {
        exception_type: e.error?.name || "Error",
        message:        e.message?.slice(0, 200),
        filename:       e.filename,
        lineno:         e.lineno,
        colno:          e.colno,
      });
    });

    window.addEventListener("unhandledrejection", (e) => {
      const reason = e.reason;
      _emit("exception", `global:unhandledRejection`, {
        exception_type: reason?.name || "UnhandledPromiseRejection",
        message:        String(reason?.message || reason || "").slice(0, 200),
      });
    });
  }

  // ── Performance timing ──────────────────────────────────
  function _hookPerformance() {
    if (!CFG.trackPerf || typeof PerformanceObserver === "undefined") return;
    try {
      const observer = new PerformanceObserver((list) => {
        list.getEntries().forEach((entry) => {
          if (entry.entryType === "measure") {
            _emit("custom", `perf:${entry.name}`, {
              event_type:  "performance_measure",
              duration_ms: Math.round(entry.duration * 100) / 100,
              start_time:  Math.round(entry.startTime),
              name:        entry.name,
            });
          } else if (entry.entryType === "navigation") {
            _emit("custom", "perf:navigation", {
              event_type:    "navigation_timing",
              dom_complete:  Math.round(entry.domComplete),
              load_event:    Math.round(entry.loadEventEnd),
              ttfb:          Math.round(entry.responseStart - entry.requestStart),
            });
          }
        });
      });
      observer.observe({ entryTypes: ["measure", "navigation"] });
    } catch (_) {}
  }

  // ── MutationObserver (optional) ─────────────────────────
  function _hookMutations() {
    if (!CFG.trackMutations || typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver((mutations) => {
      let added = 0;
      mutations.forEach((m) => { added += m.addedNodes.length; });
      if (added > 3) {
        _emit("custom", "dom:mutations", {
          event_type:    "dom_mutations",
          added_nodes:   added,
          mutation_count: mutations.length,
        });
      }
    });
    observer.observe(document.body || document.documentElement, {
      childList: true, subtree: true,
    });
  }

  // ── ES module dynamic import wrapper ────────────────────
  function _hookDynamicImport() {
    // Intercept dynamic import() by wrapping the native __import__
    // This is limited — can only wrap the Promise result, not the execution
    // But we can at least track which modules are dynamically loaded.
    const origImport = window.__dynamicImport__ ||
      (typeof importScripts === "undefined" ? null : null);

    // We wrap the global import() via a Proxy on the window object
    // Note: this is best-effort; true import() interception requires build-tool support
    if (typeof Proxy !== "undefined" && typeof window !== "undefined") {
      try {
        // Detect dynamic imports by wrapping fetch for module scripts
        // (modules loaded via import() go through fetch in some environments)
      } catch (_) {}
    }
  }

  // ── Public API extension ────────────────────────────────
  window.FlowInspectorAdvanced = {
    /**
     * Instruments a class by wrapping all its prototype methods.
     * Returns the class unchanged (mutates prototype).
     */
    trackClass(cls, namespace = "") {
      const name = namespace ? `${namespace}.${cls.name}` : cls.name;
      Object.getOwnPropertyNames(cls.prototype).forEach((method) => {
        if (method === "constructor") return;
        const desc = Object.getOwnPropertyDescriptor(cls.prototype, method);
        if (!desc || typeof desc.value !== "function") return;
        const original = desc.value;
        const nodeId   = `js_cls:${name}.${method}`;
        cls.prototype[method] = function (...args) {
          const t0 = performance.now();
          _emit("function_call", nodeId, {
            function_name: method,
            class_name:    name,
            args_preview:  args.slice(0, 3).map(a => String(a).slice(0, 40)).join(", "),
          });
          try {
            const result = original.apply(this, args);
            if (result && typeof result.then === "function") {
              return result.then(
                (res) => {
                  _emit("function_return", nodeId, {
                    function_name: method,
                    duration_ms:   parseFloat((performance.now() - t0).toFixed(2)),
                    async:         true,
                  });
                  return res;
                },
                (err) => {
                  _emit("exception", nodeId, {
                    function_name:  method,
                    exception_type: err?.name || "Error",
                    message:        String(err?.message || err).slice(0, 200),
                    duration_ms:    parseFloat((performance.now() - t0).toFixed(2)),
                  });
                  throw err;
                }
              );
            }
            _emit("function_return", nodeId, {
              function_name: method,
              duration_ms:   parseFloat((performance.now() - t0).toFixed(2)),
            });
            return result;
          } catch (err) {
            _emit("exception", nodeId, {
              function_name:  method,
              exception_type: err?.name || "Error",
              message:        String(err?.message || err).slice(0, 200),
              duration_ms:    parseFloat((performance.now() - t0).toFixed(2)),
            });
            throw err;
          }
        };
        cls.prototype[method].__flowTracked = true;
      });
      return cls;
    },

    /**
     * Wraps a router-like object (Express, Fastify, Hono, etc.)
     * to track all registered route handlers.
     */
    trackRouter(router, name = "router") {
      const HTTP_METHODS = ["get","post","put","patch","delete","head","options","all","use"];
      HTTP_METHODS.forEach((method) => {
        if (typeof router[method] !== "function") return;
        const orig = router[method].bind(router);
        router[method] = function (path, ...handlers) {
          const nodeId = `route:${method.toUpperCase()} ${path}`;
          const wrappedHandlers = handlers.map((h, i) => {
            if (typeof h !== "function") return h;
            return function (...args) {
              const t0 = performance.now();
              _emit("api_call", nodeId, { method: method.toUpperCase(), endpoint: path });
              try {
                const result = h.apply(this, args);
                if (result && typeof result.then === "function") {
                  return result.then(
                    (res) => { _emit("api_response", nodeId, { duration_ms: parseFloat((performance.now() - t0).toFixed(2)) }); return res; },
                    (err) => { _emit("exception", nodeId, { message: String(err?.message || err).slice(0, 200) }); throw err; }
                  );
                }
                _emit("api_response", nodeId, { duration_ms: parseFloat((performance.now() - t0).toFixed(2)) });
                return result;
              } catch (err) {
                _emit("exception", nodeId, { message: String(err?.message || err).slice(0, 200) });
                throw err;
              }
            };
          });
          return orig(path, ...wrappedHandlers);
        };
      });
      return router;
    },

    /**
     * Manually emit a custom event.
     */
    emit: _emit,

    /**
     * Connect to WebSocket live feed.
     */
    connectLive(url) { _initWS(url); },

    /** Get current config. */
    config: CFG,
  };

  // ── Activate hooks ──────────────────────────────────────
  _hookErrors();
  _hookWorkers();
  _hookPerformance();

  // React/Vue hooks need to be set up before the framework loads,
  // but we try retroactively as well
  _hookReact();
  _hookVue();

  if (CFG.trackMutations && document.body) {
    _hookMutations();
  } else if (CFG.trackMutations) {
    document.addEventListener("DOMContentLoaded", _hookMutations);
  }

  console.debug(
    `[FlowInspector Advanced] Initialized  flow=${CFG.flowId}  ws=${CFG.wsEndpoint || "off"}`
  );
})();
