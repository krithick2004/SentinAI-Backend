import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib

# 1. Create Dummy Data (In real project, load 'spam.csv')
# This simulates the "training" process for your research paper
data = {
    'text': [
        "Win a lottery now click here", "Your account is blocked verify immediately",
        "Hello how are you", "Meeting at 10am tomorrow",
        "Urgent! Send money to secure account", "Happy birthday friend"
    ],
    'label': [1, 1, 0, 0, 1, 0] # 1 = Phishing, 0 = Safe
}
df = pd.DataFrame(data)

# 2. Build the Model Pipeline
model = make_pipeline(CountVectorizer(), MultinomialNB())
model.fit(df['text'], df['label'])

# 3. Save the Brain
joblib.dump(model, "phishing_model.pkl")
print("Model trained and saved as phishing_model.pkl")