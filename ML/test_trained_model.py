import pandas as pd
from ML.modules.template_mining import LogTemplateMiner
from ML.modules.feature_extraction import template_count_features
from ML.modules.model_training import load_model, score_anomalies

def main():
    model_path = input("Enter the path to your trained model (e.g., ML/Clean Model Constituents/clean_Linux.joblib): ").strip()
    log_path = input("Enter the path to the log file to test: ").strip()
    try:
        with open(log_path, "r") as f:
            messages = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading log file: {e}")
        return
    try:
        model = load_model(model_path)
    except Exception as e:
        print(f"Error loading model: {e}")
        return
    miner = LogTemplateMiner()
    df_templates = miner.extract_templates(messages)
    df_templates['entity_id'] = df_templates.index
    tc = template_count_features(df_templates, template_col="template_id", entity_col="entity_id")
    scores = score_anomalies(model, tc)
    print("Anomaly Scores:")
    print(scores)

if __name__ == "__main__":
    main()
