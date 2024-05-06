import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import GridSearchCV
from torch.utils.data import DataLoader, TensorDataset
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os






data = pd.read_csv('archive/02-14-2018.csv')
#we want to actually read all of the files in here
''' This should work but not tested
files = [file for file in os.listdir('/archive') if file.endswith('.csv')]
dataframes = []
for file in files:
    full_path = os.path.join('/archive', file)
    df = pd.read_csv(full_path)
    dataframes.append(df)

data = pd.concat(dataframes, ignore_index=True)
'''



#data.fillna(data.mean(), inplace=True)

# Encode categorical features
'''
label_encoders = {}
for column in data.select_dtypes(include=['object']).columns:
    print(column)
    le = LabelEncoder()
    data[column] = le.fit_transform(data[column])
    label_encoders[column] = le
'''
data = data[["Dst Port", 'Protocol', "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "Label"]]
print(data.head())


scaler = StandardScaler()
data_scaled = scaler.fit_transform(data.drop(['Label'], axis=1))
print("Finished Scaling table")

X = data_scaled
y = data['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
print("Finished splitting into training and test")

'''
print("Starting Random Forest Training")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)


#predicting
print("Starting Random Forest Prediction")
y_pred = model.predict(X_test)
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))
print("Accuracy:", accuracy_score(y_test, y_pred))
'''

'''
#trynna use grid search to find optimal parameters
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_features': ['auto', 'sqrt', 'log2'],
    'max_depth' : [4,5,6,7,8],
    'criterion' :['gini', 'entropy']
}
CV_rfc = GridSearchCV(estimator=model, param_grid=param_grid, cv= 5)
CV_rfc.fit(X_train, y_train)
print(CV_rfc.best_params_)
'''


########################################################################################
#NEURAL NETWORK CLASSIFICATION
class AnomolyDetectionNetwork(nn.Module):
    def __init__(self):
        #Just set up some random layers, but the first and last layers need to be the same, because those based on the features and the possible outputs
        super(AnomolyDetectionNetwork, self).__init__()
        self.fc1 = nn.Linear(X_train.shape[1], 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, len(y.unique()))  

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        x = torch.relu(self.fc3(x))
        x = self.fc4(x)
        return x



print("Setting datasets into tensors")
print("Y Values", y.values)
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
X_tensor = torch.tensor(data_scaled, dtype=torch.float32)
y_tensor = torch.tensor(y_encoded, dtype=torch.long)  

X_train, X_test, y_train, y_test = train_test_split(X_tensor, y_tensor, test_size=0.3, random_state=42)

print("Creating datasets and loaders for training/testing")
train_dataset = TensorDataset(X_train, y_train)
test_dataset = TensorDataset(X_test, y_test)

train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

model = AnomolyDetectionNetwork()

criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)


def train_model(num_epochs = 1):
    for epoch in range(num_epochs):
        model.train()
        running_loss = 0.0
        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
        print(f'Epoch {epoch+1} Loss: {running_loss/len(train_loader)}')


NUM_EPOCHS = 1

print("Training model for ", NUM_EPOCHS, "Epochs")
train_model(num_epochs=NUM_EPOCHS)

def evaluate_model():
    model.eval()
    correct = 0
    total = 0
    with torch.no_grad():
        for inputs, labels in test_loader:
            outputs = model(inputs)
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
    print(f'Accuracy: {100 * correct / total}%')

print("Evaluating Model")
evaluate_model()

