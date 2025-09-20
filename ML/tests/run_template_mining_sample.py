from ML.modules.template_mining import LogTemplateMiner

def main():
    file_path = "ML/tests/test02.txt"
    try:
        with open(file_path, "r") as f:
            messages = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    miner = LogTemplateMiner()
    df_templates = miner.extract_templates(messages)
    print(df_templates)

if __name__ == "__main__":
    main()
