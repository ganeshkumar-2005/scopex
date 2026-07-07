"""
plugins/runner.py — Standalone subprocess wrapper for ScopeX plugins.
Reads configuration from stdin, instantiates the plugin with filtered arguments,
redirects standard output to stderr during scan execution, and outputs final JSON to stdout.
"""
from __future__ import annotations

import contextlib
import importlib
import inspect
import json
import sys
from typing import Any, Dict


def main():
    # Add project root (parent of plugins directory) to sys.path so plugins/tests are importable
    from pathlib import Path
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    tests_dir = project_root / "tests"
    if tests_dir.exists() and str(tests_dir) not in sys.path:
        sys.path.insert(0, str(tests_dir))

    try:
        # 1. Read payload from stdin
        input_raw = sys.stdin.read()
        if not input_raw.strip():
            print(json.dumps({"error": "Empty input"}), file=sys.stderr)
            sys.exit(1)

        input_data = json.loads(input_raw)

        # 2. Extract import target
        module_name = input_data.get("plugin_module")
        class_name = input_data.get("plugin_class")
        target = input_data.get("target")
        timeout = input_data.get("timeout", 5.0)

        if not module_name or not class_name or not target:
            print(json.dumps({"error": "Missing required fields"}), file=sys.stderr)
            sys.exit(1)

        # 3. Dynamic import
        module = importlib.import_module(module_name)
        plugin_class = getattr(module, class_name)

        # 4. Filter constructor kwargs using signature inspection
        sig = inspect.signature(plugin_class.__init__)
        valid_params = sig.parameters

        kwargs: Dict[str, Any] = {}
        
        # Check and cast context variables if the constructor accepts them
        if "discovered_subdomains" in input_data and "discovered_subdomains" in valid_params:
            kwargs["discovered_subdomains"] = input_data["discovered_subdomains"]
        if "discovered_urls" in input_data and "discovered_urls" in valid_params:
            kwargs["discovered_urls"] = input_data["discovered_urls"]
        if "existing_findings" in input_data and "existing_findings" in valid_params:
            # Reconstruct list of dict findings
            kwargs["existing_findings"] = input_data["existing_findings"]

        # 5. Redirect stdout during execution to avoid output pollution
        # This keeps prints from third-party libraries or legacy code from corrupting our JSON stdout stream
        with contextlib.redirect_stdout(sys.stderr):
            plugin = plugin_class(target, timeout=timeout, **kwargs)
            result = plugin.run()

        # 6. Output JSON to original stdout
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()

    except Exception as exc:
        # Write exception traceback to stderr and exit with non-zero code
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
