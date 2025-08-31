🔐 Cybersecurity Threat Detection & Analysis
📌 Overview

This project detects and analyzes suspicious web threat interactions using AWS CloudWatch logs, WAF logs, and Python. It combines data preprocessing, exploratory data analysis, visualization, and machine learning models to:

Identify abnormal traffic patterns.

Classify malicious requests (e.g., SQL injection, XSS, bad bots).

Generate insights & dashboards to support web security monitoring and threat hunting.

🛠️ Features

✅ Data Cleaning & Preprocessing (handle missing values, datetime parsing, feature scaling).

📊 Traffic Analysis & Visualization

Bytes In/Out distributions.

Protocol frequency.

Detection types by country.

Time-series traffic patterns.

Network graph (Source vs Destination IPs).

🧩 Feature Engineering (duration calculation, categorical encoding, correlations).

🤖 Machine Learning Models

Random Forest Classifier for suspicious request detection.

Neural Network (Dense layers) for binary classification.

CNN (1D Convolutional Model) for advanced detection.

📈 Evaluation & Insights

Accuracy, confusion matrix, classification reports.

Training/validation loss & accuracy plots.

📊 Example Outputs

Traffic Distribution Graphs

Protocol & Country-based Attack Counts

Correlation Heatmap of Features

Network Graph of IP Interactions

Model Accuracy Reports & Training Plots

📚 Tech Stack

AWS: CloudWatch, WAF Logs

Python: Pandas, NumPy, Matplotlib, Seaborn, NetworkX

ML/DL: Scikit-learn, TensorFlow/Keras

Visualization: Charts, Heatmaps, Network Graphs
