# PROJECT: AI-POWERED MALICIOUS URL DETECTION SYSTEM

Act as a Senior Machine Learning Engineer, Data Scientist, Cybersecurity Researcher and Streamlit Application Developer.

Your task is to independently develop, implement, test and deliver a COMPLETE END-TO-END AI IN CYBER SECURITY PROJECT titled:

**"AI-Powered Malicious URL Detection Using Machine Learning and Deep Learning"**

This project aims to identify malicious and phishing URLs by analysing their lexical and structural characteristics using AI.

IMPORTANT: Do not just explain how to build the project. Actually create all files, automatically download the dataset, perform EDA, implement feature extraction, train ML and DL models, generate evaluation matrices and charts, build the Streamlit application and test everything.

I should NOT have to manually download or upload the dataset.

---

## 1. AUTOMATIC DATASET ACQUISITION

Use the following official dataset:

Dataset: LegitPhish

Source: Mendeley Data

Official URL:
https://data.mendeley.com/datasets/hx4m73v2sf/2

DOI:
10.17632/hx4m73v2sf.2

Dataset details:
- Approximately 101,219 labelled URLs.
- 63,678 phishing URLs.
- 37,540 legitimate URLs.
- Original dataset contains a URL column, 17 engineered features and a target label.

Automatically download the dataset using an appropriate publicly accessible method.

Requirements:
1. Inspect the Mendeley dataset page.
2. Identify the downloadable CSV file.
3. Use the available public dataset download/API endpoint or a reliable Python download method.
4. Download the dataset without requiring manual user intervention.
5. Save the original file in data/raw/.
6. Save the processed version in data/processed/.
7. Save dataset metadata and source information.
8. Handle download failures gracefully.

If the primary download endpoint fails:
- Retry using the official Mendeley public dataset API or download endpoint.
- If the dataset is genuinely unavailable, report the problem and use the official URL-Phish dataset as a documented fallback:
  https://data.mendeley.com/datasets/65z9twcx3r/1

Do not silently switch datasets.

IMPORTANT LABEL HANDLING:

The original LegitPhish labels are:
- 0 = Phishing.
- 1 = Legitimate.

Normalize labels throughout the project to:
- 0 = Legitimate / Benign.
- 1 = Malicious / Phishing.

Clearly document the conversion.

Never assume the original label mapping.

---

## 2. PROJECT STRUCTURE

Create the following professional structure:

malicious-url-detection/
│
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── dataset_info.md
│
├── notebooks/
│   └── malicious_url_detection.ipynb
│
├── src/
│   ├── data_loader.py
│   ├── preprocessing.py
│   ├── feature_extraction.py
│   ├── eda.py
│   ├── train_models.py
│   ├── evaluate_models.py
│   └── prediction.py
│
├── models/
│   ├── logistic_regression.pkl
│   ├── decision_tree.pkl
│   ├── mlp_classifier.pkl
│   ├── best_model.pkl
│   └── preprocessing_pipeline.pkl
│
├── outputs/
│   ├── charts/
│   ├── confusion_matrices/
│   ├── reports/
│   └── model_comparison/
│
└── tests/
    ├── test_dataset.py
    ├── test_feature_extraction.py
    ├── test_models.py
    └── test_prediction.py

You may improve this structure where needed.

---

## 3. DATA UNDERSTANDING AND EDA

Load and inspect the dataset.

Perform:
- Dataset shape analysis.
- Column information.
- Data type analysis.
- Missing value analysis.
- Duplicate URL analysis.
- Class distribution.
- Statistical summary.
- Feature correlation analysis.
- URL characteristic analysis.
- Class imbalance analysis.

Create the following charts:

1. Malicious vs Legitimate URL Distribution.
2. URL Length Distribution.
3. URL Entropy Distribution.
4. Number of Subdomains Distribution.
5. HTTPS vs Non-HTTPS URL Distribution.
6. Suspicious Extension Distribution.
7. Correlation Heatmap.
8. Feature Distribution Histograms.
9. Boxplots of Important URL Features.
10. Feature Importance Graph.

Save all charts in outputs/charts/.

Use Matplotlib, Seaborn and Plotly.

Ensure all visualizations are meaningful and properly labelled.

---

## 4. URL FEATURE EXTRACTION ENGINE

THIS IS ONE OF THE MOST IMPORTANT PARTS OF THE PROJECT.

Unlike the first project, this application must accept a real URL as input.

Build a reusable feature extraction module:

src/feature_extraction.py

The module should accept a URL string and extract the features required by the trained models.

The LegitPhish dataset contains the following features:

1. url_length
2. has_ip_address
3. dot_count
4. https_flag
5. url_entropy
6. token_count
7. subdomain_count
8. query_param_count
9. tld_length
10. path_length
11. has_hyphen_in_domain
12. number_of_digits
13. tld_popularity
14. suspicious_file_extension
15. domain_name_length
16. percentage_numeric_chars

Inspect the actual dataset columns and implement all available feature definitions exactly as documented by the dataset.

IMPORTANT:
- The feature list above must be checked against the downloaded CSV.
- Preserve the exact column names and order expected by the model.
- Reproduce the dataset's feature extraction methodology as closely as possible.
- Handle missing schemes such as example.com.
- Handle IP addresses.
- Handle URLs containing ports, query parameters and fragments.
- Handle malformed or invalid input.
- Handle empty strings.
- Avoid making external requests to the submitted URL.
- Do not visit potentially malicious websites.
- Do not execute or download any URL content.

If the feature extractor cannot reproduce a dataset feature reliably, document the limitation rather than inventing its value.

Write unit tests for feature extraction.

---

## 5. DATA PREPROCESSING

Implement:
- Missing value handling.
- Duplicate removal.
- Target label normalization.
- Numeric feature validation.
- Feature scaling where required.
- Train-test splitting.
- Stratified sampling.
- Reproducible random state of 42.

Use an 80:20 train-test split.

Prevent data leakage by fitting preprocessing pipelines only on training data.

Do not include the original URL string or target label in the numerical model input unless a separately documented text-based experiment is implemented.

Keep the raw URL column available for demonstration and interpretability.

---

## 6. MACHINE LEARNING IMPLEMENTATION

Train the following supervised models:

1. Logistic Regression.
2. Decision Tree Classifier.

Requirements:
- Appropriate hyperparameters.
- Scikit-learn Pipelines.
- Suitable preprocessing.
- Reproducible training.
- Reasonable hyperparameter tuning if time permits.

Evaluate both models using:
- Accuracy.
- Precision.
- Recall.
- F1-score.
- ROC-AUC.
- Training time.
- Prediction time.

Generate:
- Confusion Matrix.
- Classification Report.
- ROC Curve.
- Precision-Recall Curve.

Explain the advantages and limitations of each model.

---

## 7. DEEP LEARNING IMPLEMENTATION

Implement an MLPClassifier neural network using Scikit-learn.

Requirements:
- Suitable hidden layers.
- ReLU activation.
- Appropriate optimizer.
- Scaled numerical features.
- Early stopping where suitable.
- Reproducible random state.
- Proper model evaluation.

Record:
- Training time.
- Prediction time.
- Accuracy.
- Precision.
- Recall.
- F1-score.
- ROC-AUC.

Generate:
- Confusion Matrix.
- Classification Report.
- Loss Curve.
- ROC Curve.
- Precision-Recall Curve.

Compare the neural network against the two ML models.

Do not fabricate or artificially inflate performance.

---

## 8. MODEL COMPARISON AND EVALUATION MATRICES

Create a comprehensive comparison table:

| Model | Accuracy | Precision | Recall | F1-score | ROC-AUC | Training Time |

Generate:
- Accuracy comparison chart.
- Precision comparison chart.
- Recall comparison chart.
- F1-score comparison chart.
- ROC-AUC comparison chart.
- Training time comparison chart.
- Confusion matrix for each model.

Clearly identify:
- True Positive.
- True Negative.
- False Positive.
- False Negative.

Save:
- Confusion matrices as PNG.
- Classification reports as CSV or TXT.
- Performance metrics as CSV and JSON.

Give special importance to malicious URL detection recall while monitoring false positives.

Choose the best model based on evaluation metrics, not accuracy alone.

---

## 9. FEATURE IMPORTANCE AND EXPLAINABILITY

Perform feature importance analysis.

For Decision Tree:
- Extract native feature importance.

For Logistic Regression:
- Analyse coefficients.

For MLP:
- Use permutation importance.

Generate a Top 10 Important URL Features chart.

Explain which URL properties contribute most to malicious URL predictions.

Provide understandable explanations for non-technical users.

---

## 10. ETHICAL AI ANALYSIS

Implement an interactive threshold experiment.

Requirements:
- Allow the user to modify the classification threshold.
- Show how the prediction changes.
- Update confusion matrices.
- Update precision and recall.
- Demonstrate false positives and false negatives.
- Explain why legitimate URLs can be flagged incorrectly.
- Discuss privacy concerns.
- Discuss model explainability limitations.
- Discuss dataset bias and generalization.

Include this as a dedicated Streamlit page.

---

## 11. JUPYTER NOTEBOOK

Create:

notebooks/malicious_url_detection.ipynb

The notebook must be complete, professional and executable.

Include these sections:

1. Project Introduction.
2. Problem Statement.
3. Dataset Description.
4. Dataset Source and Citation.
5. Automatic Dataset Download.
6. Dataset Loading.
7. Data Understanding.
8. Exploratory Data Analysis.
9. Data Visualizations.
10. Data Preprocessing.
11. URL Feature Analysis.
12. Logistic Regression.
13. Decision Tree.
14. MLP Neural Network.
15. Model Evaluation.
16. Confusion Matrices.
17. ROC and Precision-Recall Curves.
18. Model Comparison.
19. Feature Importance.
20. Ethical Analysis.
21. Final Observations.
22. Conclusion.

Use explanatory Markdown cells throughout.

Execute the complete notebook from beginning to end.

Save the executed notebook with output cells and visualizations visible.

---

## 12. STREAMLIT APPLICATION

Build a modern, attractive and fully functional cybersecurity application.

Application name:

**URLSHIELD AI**

Tagline:
"AI-Powered Malicious URL Detection and Threat Intelligence"

DESIGN:

Use a professional cybersecurity theme:
- Dark navy background.
- Black/charcoal panels.
- Cyan, electric blue and teal accents.
- Modern typography.
- Professional metric cards.
- Interactive charts.
- Sidebar navigation.
- Clean layout.
- Responsive components.
- Consistent visual design.

Do not make the interface look like a basic default Streamlit application.

Create the following pages:

### PAGE 1: SECURITY OVERVIEW

Display:
- Total URLs analysed.
- Total malicious URLs.
- Total legitimate URLs.
- Best performing model.
- Detection performance.
- Dataset distribution.
- Threat insights.

### PAGE 2: LIVE URL ANALYSIS

This is the main interactive feature.

Provide:
- URL input field.
- Analyze URL button.
- Sample URL buttons for demonstration.
- Input validation.
- Feature extraction.
- Model prediction.
- Prediction confidence.
- Risk classification.

After submitting a URL, display:

1. Original URL.
2. Extracted URL characteristics.
3. Predicted class.
4. Malicious probability.
5. Risk level.
6. Important features affecting the result.

Use clear visual indicators:

- Green: Likely Legitimate.
- Red: Potentially Malicious.
- Yellow: Uncertain / Review Recommended.

Allow users to select which trained model performs the prediction.

IMPORTANT:
- Never claim that a URL is absolutely safe.
- Clearly state that this is a machine learning-based risk prediction.
- Do not visit or open submitted URLs.
- Do not send submitted URLs to third-party services.
- Do not expose users to malicious website content.

### PAGE 3: BULK URL SCANNER

Allow users to:
- Upload CSV files containing a URL column.
- Automatically identify the URL column or let users select it.
- Extract features for each URL.
- Predict malicious or legitimate.
- Display total records.
- Display malicious URL count.
- Display legitimate URL count.
- Show a prediction table.
- Download the complete result as CSV.

### PAGE 4: THREAT INTELLIGENCE DASHBOARD

Display:
- Malicious vs legitimate URL distribution.
- URL length analysis.
- Entropy analysis.
- HTTPS usage.
- Subdomain analysis.
- Suspicious extension analysis.
- Important malicious URL indicators.

Use interactive Plotly charts.

### PAGE 5: MODEL LABORATORY

Display:
- Logistic Regression.
- Decision Tree.
- MLP Neural Network.

Show:
- Accuracy.
- Precision.
- Recall.
- F1-score.
- ROC-AUC.
- Training time.
- Prediction time.

Allow users to select models for URL prediction.

### PAGE 6: PERFORMANCE ANALYTICS

Display:
- Confusion matrices.
- Classification reports.
- ROC curves.
- Precision-Recall curves.
- Model comparison charts.
- Feature importance charts.

### PAGE 7: ETHICAL AI LAB

Implement:
- Interactive threshold slider.
- False-positive analysis.
- False-negative analysis.
- Updated confusion matrix.
- Precision-recall trade-off.
- Ethical discussion.

### PAGE 8: ABOUT THE PROJECT

Include:
- Problem statement.
- Objectives.
- Dataset description.
- Dataset citation.
- Methodology.
- Algorithms.
- Technology stack.
- Limitations.
- Future scope.

---

## 13. APPLICATION FUNCTIONALITY

Ensure the application works end-to-end.

Requirements:
- Load trained models from disk.
- Do not retrain on every Streamlit refresh.
- Use caching appropriately.
- Reuse the exact same feature extraction module used during training.
- Preserve model feature ordering.
- Validate URL inputs.
- Validate uploaded CSV files.
- Handle missing values and malformed URLs.
- Display useful error messages.
- Provide CSV downloads.
- Allow model selection.
- Ensure all charts load.
- Ensure threshold adjustments affect prediction decisions correctly.

IMPORTANT:
The feature extraction logic used during training and during live URL prediction must be consistent.

---

## 14. DOCUMENTATION

Create a professional README.md.

Include:

- Project title.
- Overview.
- Problem statement.
- Objectives.
- Dataset source.
- Dataset citation and DOI.
- Dataset statistics.
- Features used.
- Technologies.
- ML algorithms.
- DL implementation.
- Project architecture.
- Project folder structure.
- Installation instructions.
- Notebook execution instructions.
- Streamlit launch instructions.
- Model results.
- Screenshots section.
- Ethical considerations.
- Limitations.
- Future improvements.

Create requirements.txt with all dependencies.

Create a proper .gitignore.

Do not include virtual environments or unnecessary generated temporary files.

---

## 15. TESTING

Before completion:

1. Verify automatic dataset download.
2. Verify correct target label mapping.
3. Verify feature extraction.
4. Verify preprocessing.
5. Verify all three models train.
6. Verify all performance metrics.
7. Verify confusion matrices.
8. Verify all charts.
9. Verify notebook execution.
10. Verify single URL prediction.
11. Verify multiple URL prediction.
12. Verify bulk CSV upload.
13. Verify model switching.
14. Verify threshold adjustment.
15. Verify CSV downloads.
16. Verify Streamlit startup.
17. Fix all errors.

Create sample URLs and CSV records for demonstration.

Use clearly labelled illustrative examples only where actual labelled ground truth is unavailable.

Never open potentially malicious URLs during testing.

---

## 16. FINAL DELIVERABLES

Provide the complete project with:

1. Source code.
2. Automatically downloaded dataset.
3. Processed dataset.
4. Fully executed Jupyter Notebook.
5. Logistic Regression model.
6. Decision Tree model.
7. MLP Neural Network model.
8. Saved preprocessing pipeline.
9. All EDA charts.
10. All confusion matrices.
11. Classification reports.
12. Model performance comparison.
13. Fully working Streamlit application.
14. README.md.
15. requirements.txt.
16. Test results.

The application must launch using:

streamlit run app.py

The final result must be a polished university-level AI in Cyber Security project, suitable for practical evaluation and live demonstration.

Work independently and actually implement all components.

Do not stop after generating the project structure or writing initial code.

If the dataset download fails, investigate and troubleshoot the problem.

If the application has errors, fix and retest them.

Only declare the project complete after verifying that the notebook and Streamlit application work.