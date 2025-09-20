import pandas as pd
from ML.modules.template_mining import LogTemplateMiner
from ML.modules.feature_extraction import template_count_features
from ML.modules.model_training import train_isolation_forest, save_model

def main():
    file_path = input("Enter the path to your clean log file for training: ").strip()
    try:
        with open(file_path, "r") as f:
            messages = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    miner = LogTemplateMiner()
    df_templates = miner.extract_templates(messages)
    df_templates['entity_id'] = df_templates.index
    tc = template_count_features(df_templates, template_col="template_id", entity_col="entity_id")
    model = train_isolation_forest(tc)
    save_path = input("Enter the path to save the trained model (e.g., ML/clean_iforest.joblib): ").strip()
    save_model(model, save_path)
    print(f"Model trained and saved to {save_path}")

if __name__ == "__main__":
    main()
