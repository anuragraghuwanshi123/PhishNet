import os

# Dataset
DATA_DIR = 'data'
DATA_FILE_NAME = 'phishing.csv'
DATA_FILE_PATH = os.path.join(
    DATA_DIR,
    DATA_FILE_NAME
)

# Models
APP_DIR = 'app'
MODEL_DIR_NAME = 'models'
MODEL_DIR = os.path.join(
    APP_DIR,
    MODEL_DIR_NAME
)

ANN_MODEL_NAME = 'ann_model.h5'
RF_MODEL_NAME = 'rf_model.pkl'
SVM_MODEL_NAME = 'svm_model.pkl'
SCALER_NAME = 'scaler.pkl'
PCA_NAME = 'pca.pkl'

ANN_MODEL_PATH = os.path.join(
    MODEL_DIR,
    ANN_MODEL_NAME
)

RF_MODEL_PATH = os.path.join(
    MODEL_DIR,
    RF_MODEL_NAME
)

SVM_MODEL_PATH = os.path.join(
    MODEL_DIR,
    SVM_MODEL_NAME
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    SCALER_NAME
)

PCA_PATH = os.path.join(
    MODEL_DIR,
    PCA_NAME
)

# Reports
REPORT_DIR = 'reports'