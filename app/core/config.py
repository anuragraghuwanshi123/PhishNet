import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Project
    PROJECT_NAME = "PhishNet - Phishing Detection API"
    VERSION = "1.0.0"

    # Security
    API_KEY = os.getenv("API_KEY", "demo-key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secret")
    JWT_ALGORITHM = "HS256"

    # Redis
    REDIS_URL = os.getenv(
        "REDIS_URL",
        "redis://localhost:6379"
    )

    # Model paths 
    RF_MODEL_PATH = os.getenv(
        "RF_MODEL_PATH",
        "app/models/rf_model.pkl"
    )

    SVM_MODEL_PATH = os.getenv(
        "SVM_MODEL_PATH",
        "app/models/svm_model.pkl"
    )

    SCALER_PATH = os.getenv(
        "SCALER_PATH",
        "app/models/scaler.pkl"
    )

    PCA_PATH = os.getenv(
        "PCA_PATH",
        "app/models/pca.pkl"
    )

    # ANN model 
    ANN_MODEL_PATH = os.getenv(
        "ANN_MODEL_PATH",
        "app/models/ann_model.h5"
    )

    

    DATASET_PATH = os.getenv(
        "DATASET_PATH",
        "data/phishing.csv"
    )

    PHISHING_THRESHOLD = 0.5


settings = Settings()