"""
Auto-migration from ~/.pemcp/ to ~/.arkana/.

Called once at startup from config.py before cache/config initialization.
If ~/.pemcp/ exists and ~/.arkana/ does not, renames the directory.
Uses shutil.move as fallback for cross-filesystem moves.
"""
import logging
import shutil
from pathlib import Path

logger = logging.getLogger("Arkana")

_OLD_DIR = Path.home() / ".pemcp"
_NEW_DIR = Path.home() / ".arkana"


def migrate_data_dir() -> None:
    """Migrate ~/.pemcp/ to ~/.arkana/ if needed."""
    if not _OLD_DIR.exists():
        return  # Nothing to migrate

    if _NEW_DIR.exists():
        logger.info(
            "Both %s and %s exist. Skipping migration — using %s.",
            _OLD_DIR, _NEW_DIR, _NEW_DIR,
        )
        return

    try:
        # Try os.rename first (fast, same-filesystem only)
        _OLD_DIR.rename(_NEW_DIR)
        logger.info("Migrated %s → %s (rename)", _OLD_DIR, _NEW_DIR)
    except OSError:
        # Cross-filesystem fallback
        try:
            shutil.move(str(_OLD_DIR), str(_NEW_DIR))
            logger.info("Migrated %s → %s (shutil.move)", _OLD_DIR, _NEW_DIR)
        except Exception as e:
            logger.warning(
                "Failed to migrate %s → %s: %s. "
                "Old data directory will be ignored; create %s manually if needed.",
                _OLD_DIR, _NEW_DIR, e, _NEW_DIR,
            )
