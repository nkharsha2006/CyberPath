from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"
RULES_DIR = PROJECT_ROOT / "rules"
SAMPLES_DIR = PROJECT_ROOT / "samples"


def ensure_directories():
    """Create required CyberPath directories."""
    DATA_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    RULES_DIR.mkdir(exist_ok=True)
    SAMPLES_DIR.mkdir(exist_ok=True)