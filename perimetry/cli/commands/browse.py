from typing import List

import argparse
from cmd2 import with_argparser, with_category, Cmd2ArgumentParser

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from perimetry.cli.views.table_modules import display_table, module_info_table
from perimetry.cli.helpers import fuzzy_find_modules, regex_find_modules
from perimetry.core.catalog_cache import (
    SECTION_TOOL_NUMBERS,
    SECTION_NAMES,
    TOOL_TAGS,
)

__mixin_name__ = "BrowseMixin"
TEAL = "#2EC4B6"
SECTION_COLOR = "magenta"

class BrowseMixin:

    @with_category("Module Browse")
    def do_modules(self, arg: str) -> None:
        a = (arg or "").strip().lower()

        short = "-s" in a
        details = "-d" in a
        show_tags = "-t" in a
        for sw in ("-s", "-d", "-t"):
            a = a.replace(sw, "").strip()

        section_filter = None
        tag_filter = None
        if a.startswith("infra"):
            section_filter = SECTION_NAMES["network_infrastructure"]
        elif a.startswith("web"):
            section_filter = SECTION_NAMES["web_application_analysis"]
        elif a.startswith("sec"):
            section_filter = SECTION_NAMES["security_threat_intelligence"]
        elif a.startswith("tag:"):
            tag_filter = a.split(":", 1)[1]

        console = Console()
        console.print()
        display_table(
            section_filter=section_filter,
            tag_filter=tag_filter,
            short=short,
            show_tags=show_tags,
            details=details,
        )
        console.print()
        self._print_status_bar()

    _search_parser = Cmd2ArgumentParser(description="Search for modules")
    _search_parser.add_argument("keyword", help="keyword to search")
    _search_parser.add_argument("--exact", action="store_true", help="match the name substring only, no fuzzy fallback")
    _search_parser.add_argument("--case-sensitive", action="store_true", help="case sensitive search")
    _search_parser.add_argument("--regex", action="store_true", help="treat the keyword as a regular expression")

    @with_argparser(_search_parser)
    @with_category("Module Browse")
    def do_search(self, args) -> None:
        raw = args.keyword.strip()
        keyword = raw if args.case_sensitive else raw.lower()
        console = Console()

        def _field(tool, key):
            value = tool.get(key, "")
            return value if args.case_sensitive else value.lower()

        if args.regex:
            matches: List = regex_find_modules(raw)
        elif args.exact:
            matches = [m for m in fuzzy_find_modules("") if keyword in _field(m, "name")]
        else:
            fuzzy_hits: List = fuzzy_find_modules(raw)
            direct_hits = [
                m for m in fuzzy_hits
                if keyword in _field(m, "name")
                or keyword in _field(m, "description")
                or any(keyword in (t if args.case_sensitive else t.lower()) for t in TOOL_TAGS.get(m["number"], set()))
            ]
            matches = direct_hits or fuzzy_hits

        console.print()
        header = Text(f"Search: '{raw}' ", justify="center",
                    style=f"bold white on {TEAL}")
        console.print(Panel(header, expand=False, padding=(0, 2), style=TEAL))
        console.print()

        if not matches:
            console.print(f":mag_right: No modules matched '{raw}'",
                        style="bold red")
            console.print()
            self._print_status_bar()
            return

        if len(matches) == 1:
            tool = matches[0]
            console.print(module_info_table(tool, self.target, self.threads,
                                            self.module_options.get(tool["number"], {}), show_full=True))
            self.last_search_results = matches
            console.print()
            self._print_status_bar()
            return

        id_w   = max(len(t["number"]) for t in matches) + 2
        name_w = max(len(t["name"])   for t in matches) + 2

        cols = Text()
        cols.append("No.".ljust(4),             style=f"bold {TEAL}")
        cols.append("ID".ljust(id_w),           style="bold white")
        cols.append("Name".ljust(name_w),       style="bold white")
        cols.append("Section",                  style=f"bold {SECTION_COLOR}")
        console.print(cols); console.print()

        for idx, tool in enumerate(matches, 1):
            row = Text()
            row.append(f"{idx}.".ljust(4),      style=f"bold {TEAL}")
            row.append(tool["number"].ljust(id_w), style="white")
            row.append(tool["name"].ljust(name_w), style="white")
            row.append(tool["section"],            style=SECTION_COLOR)
            console.print(row)

        console.print()
        console.print(Text(" Use '<No.>' or '<ID>' with 'use' to select ",
                        style=f"bold white on {TEAL}"))
        console.print()

        self.last_search_results = matches
        self._print_status_bar()
