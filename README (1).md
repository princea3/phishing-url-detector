# Phishing URL Detector (Machine Learning)

**Author:** Prince Acharya, B.Tech CSE, IILM University
**Program:** IBM SkillsBuild Cyber Security Bootcamp 2026 (BharatCares)

## Project description
Phishing links are one of the most common ways attackers steal credentials. This project trains machine-learning
models that look **only at the text of a URL** (length, dots, hyphens, slashes, path and query structure, and so on)
and classify it as **phishing** or **legitimate**, without opening the page or contacting the host.

The notebook covers the full pipeline: data loading and cleaning, exploratory analysis, training and comparing four
models, evaluation (confusion matrix, ROC, 5-fold cross-validation), feature importance, an ablation against
network-lookup features, a bias analysis, model saving and a live prediction function for raw URLs.

## Dataset
- **Name:** Phishing-Dataset by Grega Vrbancic et al. (`dataset_small.csv`)
- **Link:** https://github.com/GregaVrbancic/Phishing-Dataset
- **Direct file:** https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv
- **Size:** 58,645 URLs, 111 features, target column `phishing` (1 = phishing, 0 = legitimate).
  After removing 1,240 duplicate rows, 57,405 remain (30,497 phishing, 26,908 legitimate).
- The notebook **downloads the file automatically** on first run (about 16 MB) into `data/`.

## Technologies used
Python 3, pandas, NumPy, scikit-learn (Logistic Regression, Decision Tree, Random Forest, Histogram Gradient Boosting),
matplotlib, seaborn, joblib, Jupyter Notebook.

## Setup and run
```bash
git clone <your-repo-url>
cd <your-repo-folder>
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
jupyter notebook PrinceAcharya_PhishingURLDetector.ipynb
```
Then choose **Kernel > Restart & Run All**. The run takes about a minute. Outputs are written to `images/`,
`models/phishing_url_model.joblib` and `results/metrics.json`.

To classify your own URL after running the notebook, call `predict_url("http://example.com/login?id=1")`
(defined in section 10); it returns the verdict and the phishing probability.

## Results (20% held-out test set, 11,481 URLs, 98 URL-only features)
| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Gradient Boosting | 0.9065 | 0.9258 | 0.8959 | 0.9106 | 0.9679 |
| Random Forest | 0.9045 | 0.9170 | 0.9020 | 0.9094 | 0.9670 |
| Decision Tree | 0.8932 | 0.9081 | 0.8890 | 0.8984 | 0.9447 |
| Logistic Regression | 0.8614 | 0.8587 | 0.8847 | 0.8715 | 0.9378 |

- Best model: **Gradient Boosting**. 5-fold cross-validated F1: **0.909 (+/- 0.003)**.
- Adding the 13 network/lookup features (DNS, WHOIS, TLS, Google index) lifts accuracy from
  0.906 to 0.956, but needs live lookups against the suspicious host.

## Key information and limitations
- **Dataset bias:** almost all bare-domain URLs are legitimate
  (phishing share 4.2%) while most URLs with a path are phishing
  (72.4%). The model partly learns "short and simple = safe", so legitimate
  deep links can be falsely flagged (false-alarm rate 19% on URLs with a path) and phishing on a
  bare domain is often missed. See section 6.2 of the notebook.
- The dataset is a snapshot in time; attackers change tactics, so periodic retraining is needed.
- `extract_features` re-implements the dataset's feature definitions and may differ slightly from the original code.
- This is a screening aid for learning purposes, not a replacement for a security gateway.

## Repository structure
```
PrinceAcharya_PhishingURLDetector.ipynb   main notebook (code + outputs)
PrinceAcharya_ProjectReport.docx          project report
requirements.txt                          Python dependencies
README.md                                 this file
01_...05_*.png                            charts used in the report
phishing_url_model.joblib                 trained model
metrics.json                              all metrics from the last run
```
When the notebook is run it saves these outputs into `images/`, `models/` and `results/` folders it creates itself.
