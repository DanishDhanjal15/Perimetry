import os, sys, json, subprocess, time, re, contextlib
from typing import Dict, List, Tuple
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from perimetry.utils.report_generator import generate_report
from perimetry.utils.util import clean_domain_input
from perimetry.core.catalog_cache import (
    tools_mapping,
)

console = Console()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")

SEVERITY_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bcritical\b|\bsevere\b|\bexploit\b|\bcompromise\b", re.I), "ALERT"),
    (re.compile(r"\bhigh\b|\balert\b|\bvulnerable\b|\bexpired\b", re.I), "ALERT"),
    (re.compile(r"\bwarn\b|\bwarning\b|\brisk\b|\bexposed\b", re.I), "WARN"),
    (re.compile(r"\bok\b|\bsecure\b|\bvalid\b", re.I), "OK"),
]

def execute_script(script_name: str, target: str, threads: int = 1, module_opts: Dict | None = None, show_status: bool = True, quiet: bool = False) -> Tuple[str, int]:
    """Run one module in its own process. Returns (captured output, exit code).

    An exit code of -1 means the script file itself was missing.
    """
    script_path = os.path.join(MODULES_DIR, script_name)
    out = ""
    if not os.path.isfile(script_path):
        console.print(f"[bold red]Missing script {script_name}[/bold red]")
        return out, -1
    ctx = console.status(f"[bold green]Running {script_name}[/bold green]", spinner="dots") if show_status else contextlib.nullcontext()
    with ctx:
        mod = os.path.splitext(script_name)[0]
        cmd = [sys.executable, "-m", f"perimetry.modules.{mod}", clean_domain_input(target), str(threads)]
        if module_opts:
            cmd.append(json.dumps(module_opts))
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        first = True
        for line in iter(proc.stdout.readline, ""):
            if not line:
                break
            l = line.rstrip("\n")
            out += l + "\n"
            if not quiet:
                console.print(l)
            elif first:
                console.print(l)
                first = False
        proc.stdout.close()
        rc = proc.wait()
        if rc and not quiet:
            console.print(f"[bold red]Script {script_name} exited {rc}[/bold red]")
    return out, rc

def parse_output_severity(text: str) -> str:
    sev = "INFO"
    for rx, label in SEVERITY_PATTERNS:
        if rx.search(text):
            if label == "ALERT":
                return "ALERT"
            if label == "WARN" and sev not in ("ALERT", "WARN"):
                sev = "WARN"
            if label == "OK" and sev == "INFO":
                sev = "OK"
    return sev

def run_modules(mod_ids: List[str], api_status: Dict[str, bool], target: str, threads: int, mode_name: str, cli_ctx, stop_on_error: bool = False) -> None:
    data: Dict[str, str] = {}
    runtimes: List[Tuple[str, str, float]] = []
    failed: List[str] = []
    total = len(mod_ids)
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.fields[module]}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("run", total=total, module="…")
        for mid in mod_ids:
            start = time.time()
            tool = tools_mapping.get(mid)
            name = tool["name"] if tool else mid
            prog.update(task, module=name)
            if tool and tool["script"]:
                allow = [o.replace("-", "_").lower() for o in (tool.get("options_meta") or [])]
                merged = _merge_options(cli_ctx.global_option_overrides, cli_ctx.module_options.get(mid), allow) if cli_ctx else {}
                out, rc = execute_script(tool["script"], target, threads, merged, show_status=False, quiet=getattr(cli_ctx, "quiet_mode", False))
                if cli_ctx:
                    cli_ctx._record_recent(mid)
                if out:
                    data[name] = out
                    sev = parse_output_severity(out)
                    runtimes.append((name, sev, time.time() - start))
                if rc:
                    failed.append(name)
                    if stop_on_error:
                        prog.advance(task)
                        console.print(f"[bold red]Stopping: {name} exited {rc} (--stop-on-error)[/bold red]")
                        break
            prog.advance(task)
    if failed:
        console.print(f"[bold yellow]{len(failed)} of {total} module(s) failed: {', '.join(failed)}[/bold yellow]")
    tag = mode_name if mode_name else "multi"
    generate_report(data, target, [tag])
    if cli_ctx:
        cli_ctx.last_run_outputs = data
        cli_ctx.last_run_runtimes = runtimes

def _merge_options(global_over: Dict | None, module_opts: Dict | None, allowed: List[str]) -> Dict:
    combined: Dict = {}
    if global_over:
        for k, v in global_over.items():
            if k in allowed and k not in combined:
                combined[k] = v
    if module_opts:
        combined.update(module_opts)
    return combined
