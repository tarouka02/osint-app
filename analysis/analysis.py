import pandas as pd

# Load the CSV
df = pd.read_csv('analysis/osint_data.csv')

# Preview
print(df.head())
print(df.info())
print(df.describe())
