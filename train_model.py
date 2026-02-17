import pandas as pd
import pickle
from sklearn.ensemble import GradientBoostingClassifier

print("Loading data...")
try:
    # Load the dataset
    data = pd.read_csv('phishing.csv')
    
    # Check if the first column is just an index (common in this dataset) and drop it if needed
    # The standard dataset has 31 columns: 30 features + 1 result
    if data.shape[1] > 31:
        data = data.iloc[:, 1:]

    # Separate features (X) and target (y)
    # The 'Result' is usually the last column
    X = data.iloc[:, :-1]
    y = data.iloc[:, -1]

    print(f"Training model with {len(X)} records...")
    
    # Initialize and train the Gradient Boosting Classifier
    gbc = GradientBoostingClassifier()
    gbc.fit(X, y)

    # Save the new model
    print("Saving model.pkl...")
    with open('pickle/model.pkl', 'wb') as file:
        pickle.dump(gbc, file)

    print("Success! New model.pkl created in pickle/ folder.")

except FileNotFoundError:
    print("Error: Could not find 'phishing.csv'. Please make sure the CSV file is in this folder.")
except Exception as e:
    print(f"An error occurred: {e}")