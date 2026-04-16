"""
Flow Inspector v4 — Python Instrumentation
============================================
Dos mecanismos de captura, sin modificación manual del código del usuario:

1. @track_flow  —  decorator explícito para casos puntuales
2. auto_instrument()  —  inyecta tracking en un módulo/clase completa sin tocar el código
3. FlowASTInjector  —  reescribe .py con AST para tracking completamente automático (Fase 4)

Uso mínimo (standalone, sin servidor):
    # already in scope, configure
    configure(flow_id="my-project", endpoint="https://myapp.onrender.com/flow-events")

    @track_flow
    def my_function(x, y):
        return x + y

Uso con servidor local:
    configure(flow_id="my-project", endpoint="http://localhost:10000/flow-events")
"""

from __future__ import annotations
import ast, functools, inspect, json, os, textwrap, threading, time, traceback
import urllib.request, urllib.error
from typing import Any, Callable, Dict, List, Optional, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


# ─── Configuration ───────────────────────────────────────

_config: Dict[str, Any] = {
    "flow_id":      os.environ.get("FLOW_ID", "default"),
    "endpoint":     os.environ.get("FLOW_ENDPOINT", "http://localhost:10000/flow-events"),
    "enabled":      os.environ.get("FLOW_ENABLED", "1") != "0",
    "sample_rate":  float(os.environ.get("FLOW_SAMPLE_RATE", "1.0")),  # 0.0-1.0
    "max_arg_len":  int(os.environ.get("FLOW_MAX_ARG_LEN", "120")),
    "batch_size":   int(os.environ.get("FLOW_BATCH_SIZE", "20")),
    "flush_ms":     int(os.environ.get("FLOW_FLUSH_MS", "2000")),
    "source":       "python",
}

def configure(
    flow_id:     Optional[str]   = None,
    endpoint:    Optional[str]   = None,
    enabled:     Optional[bool]  = None,
    sample_rate: Optional[float] = None,
) -> None:
    """Configura el tracker en runtime."""
    if flow_id     is not None: _config["flow_id"]     = flow_id
    if endpoint    is not None: _config["endpoint"]    = endpoint
    if enabled     is not None: _config["enabled"]     = enabled
    if sample_rate is not None: _config["sample_rate"] = sample_rate


# ─── Batch sender ─────────────────────────────────────────

class _BatchSender:
    """
    Acumula eventos y los envía en batch por HTTP.
    Fire-and-forget: nunca bloquea al código instrumentado.
    """

    def __init__(self):
        self._queue: List[dict] = []
        self._lock  = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._start_timer()

    def push(self, event: dict) -> None:
        with self._lock:
            self._queue.append(event)
            if len(self._queue) >= _config["batch_size"]:
                self._flush_async()

    def _start_timer(self) -> None:
        interval = _config["flush_ms"] / 1000
        self._timer = threading.Timer(interval, self._tick)
        self._timer.daemon = True
        self._timer.start()

    def _tick(self) -> None:
        self._flush_async()
        self._start_timer()

    def _flush_async(self) -> None:
        with self._lock:
            if not self._queue:
                return
            batch = self._queue[:]
            self._queue.clear()
        threading.Thread(target=self._send, args=(batch,), daemon=True).start()

    def _send(self, batch: List[dict]) -> None:
        if not batch: return
        try:
            payload = json.dumps({"events": batch}, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                _config["endpoint"].replace("/flow-events", "") + "/flow-events/batch",
                data    = payload,
                headers = {"Content-Type": "application/json"},
                method  = "POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # never raise — instrumenting code must not break it


_sender = _BatchSender()


# ─── Event builder ────────────────────────────────────────

import random
import uuid as _uuid

def _should_sample() -> bool:
    r = _config["sample_rate"]
    return r >= 1.0 or random.random() < r

def _safe_repr(obj: Any, max_len: int = None) -> str:
    """Representación segura de un objeto, truncada."""
    max_len = max_len or _config["max_arg_len"]
    try:
        s = repr(obj)
    except Exception:
        s = "<repr error>"
    return s[:max_len] + ("…" if len(s) > max_len else "")

def _make_event(
    action:        str,
    node_id:       str,
    payload:       dict,
    timestamp_ms:  Optional[int] = None,
) -> dict:
    return {
        "flow_id":      _config["flow_id"],
        "node_id":      node_id,
        "action":       action,
        "timestamp_ms": timestamp_ms or int(time.time() * 1000),
        "payload":      payload,
        "source":       _config["source"],
    }


# ─── @track_flow decorator ────────────────────────────────

def track_flow(func: F = None, *, node_id: str = None, sample_rate: float = None) -> F:
    """
    Decorator para instrumentar una función Python.

    Uso simple:
        @track_flow
        def my_func(x): ...

    Uso con opciones:
        @track_flow(node_id="custom.id", sample_rate=0.1)
        def heavy_func(): ...
    """

    def decorator(fn: F) -> F:
        qualname = fn.__qualname__
        _node_id = node_id or (
            f"method:{qualname}" if "." in qualname else f"function:{fn.__name__}"
        )

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not _config["enabled"]:
                return fn(*args, **kwargs)

            eff_rate = sample_rate if sample_rate is not None else _config["sample_rate"]
            if eff_rate < 1.0 and not (random.random() < eff_rate):
                return fn(*args, **kwargs)

            # Detect caller
            frame   = inspect.currentframe()
            caller_frame = frame.f_back if frame else None
            caller_name  = None
            if caller_frame:
                caller_fn = caller_frame.f_code.co_name
                caller_cls = caller_frame.f_locals.get("self")
                if caller_cls:
                    caller_name = f"method:{type(caller_cls).__name__}.{caller_fn}"
                elif caller_fn not in ("<module>", "<lambda>"):
                    caller_name = f"function:{caller_fn}"

            # Build args preview
            sig = inspect.signature(fn)
            params = list(sig.parameters.keys())
            args_preview_parts = []
            for i, arg in enumerate(args):
                param_name = params[i] if i < len(params) else f"arg{i}"
                if param_name == "self": continue
                args_preview_parts.append(f"{param_name}={_safe_repr(arg, 40)}")
            for k, v in kwargs.items():
                args_preview_parts.append(f"{k}={_safe_repr(v, 40)}")
            args_preview = ", ".join(args_preview_parts[:5])

            t_start = time.perf_counter()
            ts_call = int(time.time() * 1000)

            _sender.push(_make_event("function_call", _node_id, {
                "function_name": fn.__name__,
                "args_preview":  args_preview,
                "caller":        caller_name,
                "module":        fn.__module__,
            }, ts_call))

            try:
                result = fn(*args, **kwargs)
                dur_ms = (time.perf_counter() - t_start) * 1000
                ret_preview = _safe_repr(result, 60)
                _sender.push(_make_event("function_return", _node_id, {
                    "function_name":  fn.__name__,
                    "return_preview": ret_preview,
                    "duration_ms":    round(dur_ms, 2),
                }))
                return result
            except Exception as exc:
                dur_ms = (time.perf_counter() - t_start) * 1000
                _sender.push(_make_event("exception", _node_id, {
                    "function_name":  fn.__name__,
                    "exception_type": type(exc).__name__,
                    "message":        str(exc)[:200],
                    "traceback":      traceback.format_exc()[-500:],
                    "duration_ms":    round(dur_ms, 2),
                }))
                raise

        return wrapper  # type: ignore

    # Permite @track_flow sin paréntesis
    if func is not None:
        return decorator(func)
    return decorator  # type: ignore


# ─── auto_instrument: instrumenta clase o módulo entero ──

def auto_instrument(obj: Any, flow_id: str = None) -> Any:
    """
    Instrumenta automáticamente todas las funciones/métodos de:
      - una clase
      - un módulo (objeto módulo de Python)
      - un dict de funciones

    No modifica el código fuente.

    Ejemplo:
        import mymodule
        auto_instrument(mymodule)
    """
    if flow_id:
        configure(flow_id=flow_id)

    if inspect.isclass(obj):
        for name, method in inspect.getmembers(obj, predicate=inspect.isfunction):
            if name.startswith("__") and name != "__init__":
                continue
            try:
                setattr(obj, name, track_flow(method))
            except (TypeError, AttributeError):
                pass
        return obj

    if inspect.ismodule(obj):
        for name, fn in inspect.getmembers(obj, predicate=inspect.isfunction):
            if fn.__module__ == obj.__name__:  # solo funciones definidas en este módulo
                try:
                    setattr(obj, name, track_flow(fn))
                except (TypeError, AttributeError):
                    pass
        return obj

    return obj


# ─── FlowASTInjector (Fase 4) ──────────────────────────────

class FlowASTInjector:
    """
    Reescribe archivos .py inyectando @track_flow en todas las
    funciones/métodos mediante transformación AST.

    Uso:
        injector = FlowASTInjector(flow_id="my-project")
        patched_code = injector.inject_file("mymodule.py")
        # guardar o exec() el resultado

    NO modifica el archivo original — devuelve el código transformado.
    Es idempotente: detecta si @track_flow ya está presente.
    """

    DECORATOR_NAME = "track_flow"
    IMPORT_STMT    = "# already in scope"

    def __init__(self, flow_id: str = "default"):
        self.flow_id = flow_id

    def inject_file(self, path: str) -> str:
        with open(path, encoding="utf-8") as f:
            source = f.read()
        return self.inject_source(source, filename=path)

    def inject_source(self, source: str, filename: str = "<unknown>") -> str:
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return source  # no podemos parsear, devolver intacto

        transformer = _TrackFlowTransformer(self.DECORATOR_NAME)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)

        try:
            import ast as _ast
            result = ast.unparse(new_tree)
        except AttributeError:
            # Python < 3.9 no tiene ast.unparse
            return source

        # Agregar import si aún no está
        if self.IMPORT_STMT not in result:
            result = self.IMPORT_STMT + "\n" + result

        return result

    def inject_directory(self, dirpath: str, output_dir: str = None) -> Dict[str, str]:
        """
        Inyecta tracking en todos los .py de un directorio.
        Si output_dir es None, genera archivos .flow_instrumented.py al lado.
        """
        results = {}
        for root, _, files in os.walk(dirpath):
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                patched = self.inject_file(fpath)

                if output_dir:
                    rel     = os.path.relpath(fpath, dirpath)
                    outpath = os.path.join(output_dir, rel)
                    os.makedirs(os.path.dirname(outpath), exist_ok=True)
                else:
                    outpath = fpath.replace(".py", ".flow_instrumented.py")

                with open(outpath, "w", encoding="utf-8") as f:
                    f.write(patched)
                results[fpath] = outpath
        return results


class _TrackFlowTransformer(ast.NodeTransformer):
    """Visitor AST que agrega @track_flow a funciones/métodos."""

    def __init__(self, decorator_name: str):
        self.deco_name = decorator_name

    def _has_decorator(self, node) -> bool:
        for d in node.decorator_list:
            if isinstance(d, ast.Name) and d.id == self.deco_name:
                return True
            if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == self.deco_name:
                return True
        return False

    def _should_skip(self, node) -> bool:
        """Omite dunders (excepto __init__) y funciones muy cortas."""
        if node.name.startswith("__") and node.name not in ("__init__", "__call__"):
            return True
        # funciones de 1 línea (getters triviales)
        body = node.body
        if len(body) == 1 and isinstance(body[0], (ast.Return, ast.Pass)):
            return True
        return False

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if not self._has_decorator(node) and not self._should_skip(node):
            deco = ast.Name(id=self.deco_name, ctx=ast.Load())
            node.decorator_list.insert(0, deco)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef
