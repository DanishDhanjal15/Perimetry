from __future__ import annotations

import argparse
from typing import List

from cmd2 import with_argparser, with_category, Cmd2ArgumentParser
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from perimetry.core.runner import run_modules
from perimetry.cli.helpers import resolve_module_number, fuzzy_find_modules
from perimetry.core.catalog_cache import SECTION_TOOL_NUMBERS, tools_mapping

__mixin_name__ = "RunMixin"

TEAL = "#2EC4B6"
console = Console()

# Order used by BEAST MODE and by the "Run All …" catalog entries.
ALL_SECTIONS = (
    "Network & Infrastructure",
    "Web Application Analysis",
    "Security & Threat Intelligence",
)


class RunMixin:
    _run_parser = Cmd2ArgumentParser(description="Run modules")
    _run_parser.add_argument("ids", nargs="*", help="[module ids] or target override")
    _run_parser.add_argument("--dry-run", action="store_true", help="show what would be run without executing")
    _run_parser.add_argument("--stop-on-error", action="store_true", help="abort the chain as soon as a module exits non-zero")
    _run_parser.add_argument("--continue-on-error", action="store_true", help="keep going when a module fails (this is the default)")

    @with_argparser(_run_parser)
    @with_category("Execution")
    def do_run(self, args) -> None:
        ids: List[str] = args.ids
        stop_on_error = args.stop_on_error and not args.continue_on_error

        if ids:
            mod_ids, target_override = self._parse_run_tokens(ids)
            if not mod_ids:
                self.perror("No valid module ids supplied.")
                return
            if args.dry_run:
                self._print_dry_run(mod_ids)
                return
            if target_override:
                self.target = target_override
            if not self.target:
                self._prompt_target_if_needed()
            self._invoke_runner(mod_ids, mode_name="CHAIN", stop_on_error=stop_on_error)
            return

        if not self.selected_module:
            self.perror("No module selected.")
            return

        # "Run All …" and BEAST MODE are catalog entries with no script of their
        # own; they stand for a whole section (or every section).
        if not self.selected_module.get("script"):
            expanded = self._expand_selection()
            if not expanded:
                self.pwarning("No modules found for that selection.")
                return
            if args.dry_run:
                self._print_dry_run(expanded)
                return
            if not self.target:
                self._prompt_target_if_needed()
            self._invoke_runner(expanded, mode_name=self.selected_module["name"].upper().replace(" ", "_"), stop_on_error=stop_on_error)
            return

        if args.dry_run:
            console.print(f"[yellow]DRY RUN: Would execute {self.selected_module['name']}[/yellow]")
            return

        if not self.target:
            self._prompt_target_if_needed()
        self._invoke_single(self.selected_module, stop_on_error=stop_on_error)

    def _print_dry_run(self, mod_ids: List[str]) -> None:
        console.print(f"[yellow]DRY RUN: Would execute {len(mod_ids)} modules[/yellow]")
        for mid in mod_ids:
            mod = tools_mapping.get(mid)
            if mod:
                console.print(f"  - {mid}: {mod['name']}")

    def _parse_run_tokens(self, tokens: List[str]) -> tuple[List[str], str | None]:
        mod_ids: List[str] = []
        target_override = None
        for tok in tokens:
            if "." in tok and not tok.isdigit() and target_override is None:
                target_override = tok
                continue
            rid = resolve_module_number(tok) if tok.isdigit() else None
            if rid:
                mod_ids.append(rid)
                continue
            match = fuzzy_find_modules(tok)
            if match:
                mod_ids.append(match[0]["number"])
        return mod_ids, target_override

    def _invoke_runner(self, mod_ids: List[str], mode_name: str, stop_on_error: bool = False) -> None:
        self.last_run_ids = list(mod_ids)
        self.last_run_mode = mode_name
        run_modules(mod_ids, self.api_status, self.target, self.threads, mode_name, self, stop_on_error)

    def _invoke_single(self, module: dict, stop_on_error: bool = False) -> None:
        self._invoke_runner([module["number"]], mode_name=module["name"], stop_on_error=stop_on_error)

    _runall_parser = Cmd2ArgumentParser(description="Run all modules in category")
    _runall_parser.add_argument("category", choices=["infrastructure", "web", "security", "all"])
    _runall_parser.add_argument("--stop-on-error", action="store_true", help="abort as soon as a module exits non-zero")

    @with_argparser(_runall_parser)
    @with_category("Execution")
    def do_runall(self, args) -> None:
        cat_map = {
            "infrastructure": ["Network & Infrastructure"],
            "web": ["Web Application Analysis"],
            "security": ["Security & Threat Intelligence"],
            "all": list(ALL_SECTIONS),
        }
        mod_ids: List[str] = []
        for section in cat_map[args.category]:
            mod_ids.extend(SECTION_TOOL_NUMBERS.get(section, []))
        if not mod_ids:
            self.perror("No modules in that category.")
            return
        if not self.target:
            self._prompt_target_if_needed()
        self._invoke_runner(mod_ids, mode_name=f"ALL_{args.category.upper()}", stop_on_error=args.stop_on_error)

    @with_category("Execution")
    def do_runfav(self, _line) -> None:
        self._fav_run()

    @with_category("Execution")
    def do_last(self, _line) -> None:
        if not getattr(self, "last_run_ids", None):
            self.perror("Nothing has been run yet.")
            return
        if not self.target:
            self._prompt_target_if_needed()
        console.print(Panel(f"Re-running: {', '.join(self.last_run_ids)}", border_style=TEAL))
        self._invoke_runner(self.last_run_ids, mode_name=self.last_run_mode or "LAST")

    def _expand_selection(self) -> List[str]:
        """Turn a scriptless catalog entry into the list of modules it stands for."""
        sel = self.selected_module
        if sel.get("section") == "Special Mode":          # BEAST MODE
            sections = list(ALL_SECTIONS)
        elif "Infrastructure" in sel["name"]:
            sections = ["Network & Infrastructure"]
        elif "Web Intelligence" in sel["name"]:
            sections = ["Web Application Analysis"]
        elif "Security" in sel["name"]:
            sections = ["Security & Threat Intelligence"]
        else:
            return []
        mod_ids: List[str] = []
        for section in sections:
            mod_ids.extend(SECTION_TOOL_NUMBERS.get(section, []))
        return mod_ids
