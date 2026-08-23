from pathlib import Path


def load_config(path: str) -> str:
    """Load a network-device configuration file."""
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    if not config_path.is_file():
        raise ValueError(f"Configuration path is not a file: {path}")

    return config_path.read_text(encoding="utf-8")