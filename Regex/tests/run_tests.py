import sys
import pytest
from pathlib import Path

if __name__ == "__main__":
    # Run pytest on the tests folder
    root = Path(__file__).resolve().parent
    sys.exit(pytest.main([str(root), "-q"]))
