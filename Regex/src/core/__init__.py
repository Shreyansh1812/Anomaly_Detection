"""Core package: models and interfaces."""
try:
    from .standard_log import StandardLog  # noqa: F401
except Exception:
    pass
try:
    from .interfaces import LogReader  # noqa: F401
except Exception:
    pass
