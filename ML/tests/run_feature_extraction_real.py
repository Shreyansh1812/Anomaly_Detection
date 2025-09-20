import pandas as pd
from ML.modules.template_mining import LogTemplateMiner
from ML.modules.feature_extraction import template_count_features, tfidf_features, aggregate_features

def main():
    file_path = "Data/generated/Log_Testing_01.log"
    try:
        with open(file_path, "r") as f:
            messages = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    miner = LogTemplateMiner()
    df_templates = miner.extract_templates(messages)
    # Treat each log line as a separate entity
    df_templates['entity_id'] = df_templates.index
    # Template count features
    tc = template_count_features(df_templates, template_col="template_id", entity_col="entity_id")
    print("Template Count Features:")
    print(tc)
    # TF-IDF features
    tfidf = tfidf_features(df_templates, text_col="message", entity_col="entity_id")
    print("TF-IDF Features:")
    print(tfidf)
    # Aggregate features: only if columns exist
    required_cols = {"status", "bytes", "path"}
    if required_cols.issubset(df_templates.columns):
        agg = aggregate_features(df_templates, entity_col="entity_id")
        print("Aggregate Features:")
        print(agg)
    else:
        print("Aggregate Features: Skipped (columns not present)")

if __name__ == "__main__":
    main()
