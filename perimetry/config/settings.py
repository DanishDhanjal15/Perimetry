import os
# config/settings.py


def _load_dotenv():
    """Read KEY=VALUE pairs from a .env file next to the project root.

    Keeps real credentials out of this tracked file - .env is gitignored.
    Existing environment variables always win.
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for path in (os.path.join(root, ".env"), os.path.join(os.getcwd(), ".env")):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip().strip("'\""))
        except OSError:
            pass
        break


_load_dotenv()

RESULTS_DIR = "results"

DEFAULT_TIMEOUT = 10

USER_AGENT = "Mozilla/5.0 (compatible; PerimetryRecon/2.0)"

API_KEYS = {
    "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", ""),
    "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", ""),
    # Legacy Censys Search v2 credentials (Basic auth). Superseded by the
    # single Platform API token below, which is what new accounts are issued.
    "CENSYS_API_ID": os.getenv("CENSYS_API_ID", ""),
    "CENSYS_API_SECRET": os.getenv("CENSYS_API_SECRET", ""),
    "CENSYS_API_KEY": os.getenv("CENSYS_API_KEY", ""),
    "SSL_LABS_API_KEY": os.getenv("SSL_LABS_API_KEY", ""),
    "HIBP_API_KEY": os.getenv("HIBP_API_KEY", ""),
}

# Community string used by the SNMP modules for read-only queries.
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")

EXPORT_SETTINGS = {
    "enable_txt_export": True,
    "enable_csv_export": False
}

LOG_SETTINGS = {
    "enable_logging": True,
    "log_file": "perimetry.log",
    "log_level": "INFO"
}

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "en-US,en;q=0.9"
}

DEFAULT_THREADS = 1
DEFAULT_MAX_PAGES = 100
DEFAULT_WARN_MS = 3000
DEFAULT_FULL_CHAIN = 0
DEFAULT_QUIET = False
DEFAULT_COLOR = True
DEFAULT_WRAP_WIDTH = None

PROFILE_DEFAULTS = {
    "speed": {
        "max_pages": 50,
        "warn_ms": 1000,
        "full_chain": 0,
        "threads_min": 2
    },
    "deep": {
        "max_pages": 1000,
        "warn_ms": 5000,
        "full_chain": 1,
        "threads_min": 5
    },
    "safe": {
        "max_pages": 25,
        "warn_ms": 2000,
        "full_chain": 0,
        "threads_min": 1
    }
}

from multiprocessing import cpu_count
DEFAULT_THREAD_CAP = min(32, cpu_count() * 5)
