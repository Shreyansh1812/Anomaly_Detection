import pandas as pd

# Path to Linux clean dataset
csv_path = r"C:\\Users\\shrey\\Downloads\\SGP-II\\Regex\\Data\\raw_logs\\Linux_2k.log_structured.csv"
# Output sample log file
output_path = r"C:\\Users\\shrey\\Downloads\\SGP-II\\ML\\Extracted Features\\linux.log"

def main():
    df = pd.read_csv(csv_path)
    # Get unique EventTemplates
    templates = df['EventTemplate'].unique()
    # Write each template as a line in the sample log file
    with open(output_path, 'w') as f:
        for template in templates:
            f.write(f"{template}\n")
    print(f"Sample log file created with {len(templates)} lines at {output_path}")

if __name__ == "__main__":
    main()
