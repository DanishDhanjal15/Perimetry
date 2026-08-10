"""Fast, network-free smoke tests: catalog integrity, compilation, imports.

These assert the suite is structurally sound without touching the network, so
they run reliably in CI. Deeper behaviour of the new modules is covered in
test_new_modules.py.
"""
import importlib
import os
import py_compile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(ROOT, "perimetry", "modules")

from perimetry.core.catalog_cache import tools  # noqa: E402

# Catalog entries that point at a real module script.
CATALOG = [t for t in tools if t.get("script")]

# The seven modules added by this fork — they must import cleanly and expose run().
NEW_MODULES = [
    "jarm_tls_fingerprint",
    "js_secret_scanner",
    "subdomain_takeover_deep",
    "cve_tech_enrichment",
    "sri_integrity_checker",
    "security_headers_grade",
    "document_metadata_extractor",
]


def _all_py_files():
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "perimetry")):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


@pytest.mark.parametrize("path", list(_all_py_files()))
def test_python_file_compiles(path):
    py_compile.compile(path, doraise=True)


def test_catalog_ids_unique():
    ids = [t["number"] for t in tools]
    assert len(ids) == len(set(ids)), "duplicate module IDs in the catalog"


def test_catalog_names_unique():
    names = [t["name"] for t in tools]
    assert len(names) == len(set(names)), "duplicate module names in the catalog"


@pytest.mark.parametrize("tool", CATALOG, ids=lambda t: t["number"])
def test_catalog_script_exists(tool):
    assert os.path.isfile(os.path.join(MODULES_DIR, tool["script"])), \
        f"catalog entry {tool['number']} points at missing {tool['script']}"


def test_no_orphan_module_files():
    referenced = {t["script"] for t in CATALOG}
    on_disk = {f for f in os.listdir(MODULES_DIR) if f.endswith(".py") and f != "__init__.py"}
    assert not (on_disk - referenced), f"module files not in catalog: {sorted(on_disk - referenced)}"


@pytest.mark.parametrize("sub", ["cli", "core", "utils", "config"])
def test_core_packages_import(sub):
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "perimetry", sub)):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), ROOT)
            dotted = rel[:-3].replace(os.sep, ".").removesuffix(".__init__")
            importlib.import_module(dotted)


@pytest.mark.parametrize("mod", NEW_MODULES)
def test_new_module_imports_and_has_run(mod):
    m = importlib.import_module(f"perimetry.modules.{mod}")
    assert callable(getattr(m, "run", None)), f"{mod} does not expose a run() entry point"
