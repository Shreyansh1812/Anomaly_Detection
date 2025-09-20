import pandas as pd


# Input path: Linux clean dataset
csv_path = r"C:\Users\shrey\Downloads\SGP-II\Regex\Data\raw_logs\Linux_2k.log_structured.csv"
# Output path: where extracted features will be saved
output_path = r"C:\Users\shrey\Downloads\SGP-II\ML\Extracted Features\linux_101_features.txt"

def main():
    df = pd.read_csv(csv_path)
    templates = df['EventTemplate'].unique()
    with open(output_path, 'w') as f:
        for template in templates:
            f.write(f"{template}\n")
    print(f"Extracted {len(templates)} unique feature templates to {output_path}")

if __name__ == "__main__":
    main()
