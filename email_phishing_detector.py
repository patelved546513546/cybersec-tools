import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Load real dataset
data = pd.read_csv('sms_spam.csv', sep='\t', header=None, names=['label', 'message'])

# Split data
X_train, X_test, y_train, y_test = train_test_split(data['message'], data['label'], test_size=0.2)

# Convert text to numbers
vectorizer = CountVectorizer()
X_train_vectors = vectorizer.fit_transform(X_train)
X_test_vectors = vectorizer.transform(X_test)

# Train Naive Bayes classifier
model = MultinomialNB()
model.fit(X_train_vectors, y_train)

# Test accuracy
predicted = model.predict(X_test_vectors)
print("Accuracy:", accuracy_score(y_test, predicted))

# Real email phishing detection
phishing_keywords = ["verify", "click here", "password reset", "urgent", "confirm account"]

email = input("\nPaste your email/message here:\n")
email_vector = vectorizer.transform([email])
result = model.predict(email_vector)[0]

phishing_flag = any(keyword.lower() in email.lower() for keyword in phishing_keywords)

print("\n--- Results ---")
print("Spam/Ham Detection:", result)
print("Phishing Keywords Found!" if phishing_flag else "No phishing keywords detected.")
