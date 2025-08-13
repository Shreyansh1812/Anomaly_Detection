import argparse
import sys
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from src.log_processing import LogReaderFactory  # type: ignore
from src.model.model_training import train_isolation_forest, save_artifacts  # type: ignore


def main():
    ap = argparse.ArgumentParser(description="Train IsolationForest on a log file and save artifacts")
    ap.add_argument("--input", required=True, help="Path to training log file")
    ap.add_argument("--out", required=False, default=str(ROOT / "Models"), help="Output directory for artifacts")
    ap.add_argument("--contamination", required=False, type=float, default=0.02, help="Contamination rate")
    args = ap.parse_args()

    reader = LogReaderFactory.create_reader(args.input)
    df = reader.read()

    model, featurizer = train_isolation_forest(df)
    paths = save_artifacts(model, featurizer, args.out)
    print(f"Saved model: {paths['model']}")
    print(f"Saved featurizer: {paths['featurizer']}")


if __name__ == "__main__":
    main()
