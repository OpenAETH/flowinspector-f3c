# Third-party notices

Flow Inspector's unified-graph engine can use the following projects. None is vendored in this
repository; each is installed separately and is optional.

| Project | Version evaluated | License | How it is used |
|---|---|---|---|
| [py-tree-sitter](https://github.com/tree-sitter/py-tree-sitter) | 0.26.0 | MIT | Python dependency (`requirements-optional.txt`), imported in-process |
| [tree-sitter-python](https://github.com/tree-sitter/tree-sitter-python) | 0.25.0 | MIT | Python dependency (`requirements-optional.txt`), grammar |
| [scip-python](https://github.com/sourcegraph/scip-python) (`@sourcegraph/scip-python`) | 0.6.6 | MIT (includes Microsoft Pyright, MIT) | External CLI run as a subprocess; **not linked or bundled**. Its 43 transitive npm packages are MIT (29), ISC (9), BSD-3-Clause (2), Apache-2.0 (2) and `google-protobuf` (BSD-3-Clause AND Apache-2.0) |
| [codemap](https://github.com/kogriv/codemap) (PyPI: `codmap`) | 0.0.21 | MIT | **Reference only**: not a dependency. Used to cross-check call-graph output and as design input (confidence labels, determinism) |

The SCIP wire format (https://github.com/sourcegraph/scip, `scip.proto`) is read by a small
decoder in `Backend/graph/scip_reader.py`, written from the published field numbers; no protobuf
runtime is required.
