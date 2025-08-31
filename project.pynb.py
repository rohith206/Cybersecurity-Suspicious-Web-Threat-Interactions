import pandas as pd
 
df = pd.read_csv(r'C:\Users\shank\Downloads\CloudWatch_Traffic_Web_Attack.csv')


df.info()
df.head()

missing_values = df.isnull().sum()

df['bytes_in'].fillna(df['bytes_in'].median())
df.dropna(subset=['src_ip', 'dst_ip'], inplace=True)

import pandas as pd

# Load the CSV
df = pd.read_csv(r'C:\Users\shank\Downloads\CloudWatch_Traffic_Web_Attack.csv')

# Convert to datetime, force errors to NaT
df['creation_time'] = pd.to_datetime(df['creation_time'], errors='coerce')
df['end_time'] = pd.to_datetime(df['end_time'], errors='coerce')

# Print how many conversions failed
print("Invalid creation_time entries:", df['creation_time'].isna().sum())
print("Invalid end_time entries:", df['end_time'].isna().sum())

# Drop rows with bad datetimes if needed
df.dropna(subset=['creation_time', 'end_time'], inplace=True)

# Confirm datatypes
print(df.dtypes)

import matplotlib.pyplot as plt
import seaborn as sns

plt.figure(figsize=(12, 6))
sns.histplot(df['bytes_in'], bins=50, color='blue', kde=True,
label='Bytes In')
sns.histplot(df['bytes_out'], bins=50, color='red', kde=True,
label='Bytes Out')
plt.legend()
plt.title('Distribution of Bytes In and Bytes Out')
plt.show()

plt.figure(figsize=(10, 5))
sns.countplot(x='protocol', data=df, palette='viridis')
plt.title('Protocol Count')
plt.xticks(rotation=45)
plt.show()

df_unique = df.drop_duplicates()
df_unique['creation_time'] 
pd.to_datetime(df_unique['creation_time'])
df_unique['end_time'] = pd.to_datetime(df_unique['end_time'])
df_unique['time'] = pd.to_datetime(df_unique['time'])
df_unique['src_ip_country_code']
df_unique['src_ip_country_code'].str.upper() 
print("Unique Datasets Information:")
df_unique.info()

print("Top 5 Unique Datasets Information:")
print(df_unique.head())

from sklearn.preprocessing import StandardScaler, OneHotEncoder


df_unique['duration_seconds'] = (df_unique['end_time'] - df_unique['creation_time']).dt.total_seconds()
scaler = StandardScaler()
scaled_features = scaler.fit_transform(df_unique[['bytes_in','bytes_out', 'duration_seconds']])

# OneHotEncoder for categorical features
encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
encoded_features = encoder.fit_transform(df_unique[['src_ip_country_code']])
 # Combining transformed features back into the DataFrame
scaled_columns = ['scaled_bytes_in', 'scaled_bytes_out','scaled_duration_seconds']
encoded_columns = encoder.get_feature_names_out(['src_ip_country_code'])

 # Combining transformed features back into the DataFrame
scaled_columns = ['scaled_bytes_in', 'scaled_bytes_out','scaled_duration_seconds']
encoded_columns = encoder.get_feature_names_out(['src_ip_country_code'])

 # Convert numpy arrays back to DataFrame
scaled_df = pd.DataFrame(scaled_features,columns=scaled_columns, index=df_unique.index)
encoded_df = pd.DataFrame(encoded_features,columns=encoded_columns, index=df_unique.index)
# Concatenate all the data back together
transformed_df=pd.concat([df_unique,scaled_df,encoded_df],axis=1)
 # Displaying the transformed data
print("Transformed data is...!!")
print(transformed_df.head())

 # Compute correlation matrix for numeric columns only
numeric_df = transformed_df.select_dtypes(include=['float64','int64'])
correlation_matrix_numeric = numeric_df.corr()
 # Display the correlation matrix
print("the correlation matrix is...!!")
print(correlation_matrix_numeric)

 # Heatmap for the correlation matrix
plt.figure(figsize=(10,8))
sns.heatmap(correlation_matrix_numeric,annot=True,fmt=".2f",cmap='coolwarm')
plt.title('CorrelationMatrixHeatmap')
plt.show()

 # Stacked Bar Chart for Detection Types by Country
 # Preparing data for stacked bar chart
detection_types_by_country = pd.crosstab(transformed_df['src_ip_country_code'],
 transformed_df['detection_types'])
detection_types_by_country.plot(kind='bar', stacked=True,
 figsize=(12, 6))
plt.title('Detection Types by Country Code')
plt.xlabel('Country Code')
plt.ylabel('Frequency of Detection Types')
plt.xticks(rotation=45)
plt.legend(title='Detection Type')
plt.show()

# Convert 'creation_time' to datetime format
df['creation_time'] = pd.to_datetime(df['creation_time'])
 # Set 'creation_time' as the index
df.set_index('creation_time', inplace=True)
 # Plotting
plt.figure(figsize=(12, 6))
plt.plot(df.index, df['bytes_in'], label='Bytes In',marker='o')
plt.plot(df.index, df['bytes_out'], label='Bytes Out',marker='o')
plt.title('Web Traffic Analysis Over Time')
plt.xlabel('Time')
plt.ylabel('Bytes')
plt.legend()
plt.grid(True)
plt.xticks(rotation=45)
plt.tight_layout()
 # Show the plot
plt.show()

 # Create a graph
import networkx as nx
G = nx.Graph()
 # Add edges from source IP to destination IP
for idx, row in df.iterrows():G.add_edge(row['src_ip'], row['dst_ip'])
 # Draw the network graph
plt.figure(figsize=(14, 10))
nx.draw_networkx(G, with_labels=True, node_size=20,
 font_size=8, node_color='skyblue', font_color='darkblue')
plt.title('Network Interaction between Source and DestinationIPs')
plt.axis('off') # Turn off the axis
 # Show the plot
plt.show()

 # First, encode this column into binary labels
transformed_df['is_suspicious'] =(transformed_df['detection_types'] == 'waf_rule').astype(int)
 # Features and Labels
X = transformed_df[['bytes_in', 'bytes_out','scaled_duration_seconds']] # Numeric features
y = transformed_df['is_suspicious'] # Binary labels

 # Split the data into training and test sets
# Required imports
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

X_train, X_test, y_train, y_test = train_test_split(X, y,test_size=0.3, random_state=42)
 # Initialize the Random Forest Classifier
rf_classifier = RandomForestClassifier(n_estimators=100,random_state=42)
 # Train the model
rf_classifier.fit(X_train, y_train)
 # Predict on the test set
y_pred = rf_classifier.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
classification = classification_report(y_test, y_pred)
print("Model Accuracy: ",accuracy)
print("Classification Report: ",classification)

from keras.models import Sequential
from keras.layers import Dense
from keras.optimizers import Adam
df['is_suspicious'] = (df['detection_types'] =='waf_rule').astype(int)
 # Features and labels
X = df[['bytes_in', 'bytes_out']].values # Using only numeric features
y = df['is_suspicious'].values
 # Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y,test_size=0.3, random_state=42)
 # Normalize features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
 # Neural network model
model = Sequential([Dense(8, activation='relu',input_shape=(X_train_scaled.shape[1],)),Dense(16, activation='relu'),
Dense(1, activation='sigmoid')])
 # Compile the model
model.compile(optimizer=Adam(), loss='binary_crossentropy',metrics=['accuracy'])
 # Train the model
history = model.fit(X_train_scaled, y_train, epochs=10,batch_size=8, verbose=1)
 # Evaluate the model
loss, accuracy = model.evaluate(X_test_scaled, y_test)
print(f"Test Accuracy: {accuracy*100:.2f}%")

 # Neural network model
import matplotlib.pyplot as plt
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.optimizers import Adam
model = Sequential([Dense(128, activation='relu',input_shape=(X_train_scaled.shape[1],)),Dropout(0.5),
 Dense(128, activation='relu'),Dropout(0.5),
 Dense(1, activation='sigmoid')
 ])
 # Compile the model
model.compile(optimizer=Adam(), loss='binary_crossentropy',metrics=['accuracy'])
 # Train the model
history = model.fit(X_train_scaled, y_train, epochs=10,batch_size=32, verbose=1, validation_split=0.2)
 # Evaluate the model
loss, accuracy = model.evaluate(X_test_scaled, y_test)
print(f"Test Accuracy: {accuracy*100:.2f}%")
# Plotting the training history
plt.figure(figsize=(12, 6))
plt.subplot(1, 2, 1)
plt.plot(history.history['accuracy'], label='TrainingAccuracy')
plt.plot(history.history['val_accuracy'], label='ValidationAccuracy')
plt.title('Model Accuracy')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend()
plt.subplot(1, 2, 2)
plt.plot(history.history['loss'], label='Training Loss')
plt.plot(history.history['val_loss'], label='Validation Loss')
plt.title('Model Loss')
plt.xlabel('Epoch')
plt.ylabel('Loss')
plt.legend()
plt.show()

import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from keras.models import Sequential
from keras.layers import Conv1D, Flatten, Dense, Dropout
from keras.optimizers import Adam
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train.reshape(-1,
X_train.shape[-1])).reshape(X_train.shape)
X_test_scaled = scaler.transform(X_test.reshape(-1,
X_test.shape[-1])).reshape(X_test.shape)
# Adjusting the network to accommodate the input size
model = Sequential([Conv1D(32, kernel_size=1, activation='relu',
 input_shape=(X_train_scaled.shape[1], 1)),
 Flatten(),
 Dense(64, activation='relu'),
 Dropout(0.5),
 Dense(1, activation='sigmoid')
 ])
 # Compile the model
model.compile(optimizer=Adam(), loss='binary_crossentropy',metrics=['accuracy'])
 # Train the model
history = model.fit(X_train_scaled, y_train, epochs=10,
 batch_size=32, verbose=1, validation_split=0.2)
 # Evaluate the model
loss, accuracy = model.evaluate(X_test_scaled, y_test)
print(f"Test Accuracy: {accuracy*100:.2f}%")
 # Plotting the training history
plt.figure(figsize=(12, 6))
plt.subplot(1, 2, 1)
plt.plot(history.history['accuracy'], label='TrainingAccuracy')
plt.plot(history.history['val_accuracy'], label='ValidationAccuracy')
plt.title('Model Accuracy')
plt.xlabel('Epoch')
plt.ylabel('Accuracy')
plt.legend()
plt.subplot(1, 2, 2)
plt.plot(history.history['loss'], label='Training Loss')
plt.plot(history.history['val_loss'], label='Validation Loss')
plt.title('Model Loss')
plt.xlabel('Epoch')
plt.ylabel('Loss')
plt.legend()
plt.show()