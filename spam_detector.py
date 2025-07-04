from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Sample dataset
data = [
    ("spam", "Win a free iPhone now!"),
    ("ham", "Let's catch up tomorrow"),
    ("spam", "You have won $1000 cash"),
    ("ham", "Meeting is at 5 PM today"),
    ("spam", "Claim your free prize now"),
]

# Split into labels and messages
labels, texts = zip(*data)

# Convert text to numbers
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(texts)

# Split into train/test
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.3)

# Train Naive Bayes model
model = MultinomialNB()
model.fit(X_train, y_train)

# Test the model
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))

# Predict new input
message = input("Enter a message: ")
msg_vector = vectorizer.transform([message])
result = model.predict(msg_vector)
print("This is:", result[0])
