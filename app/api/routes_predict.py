from fastapi import APIRouter, UploadFile, File, Depends
from pydantic import BaseModel, Field

from app.core.dependencies import get_api_key, get_current_user
from app.services.model_service import (
    predict_phishing,
    predict_manual_features,
    predict_batch_csv,
    evaluate_model
)

router = APIRouter()


class URLRequest(BaseModel):
    url: str = Field(..., example="https://www.google.com")
    model_name: str = Field(default="Random Forest")


class ManualFeatureRequest(BaseModel):
    features: list[int] = Field(..., min_length=30, max_length=30)
    model_name: str = Field(default="Random Forest")


@router.post("/predict/url")
def predict_url(
    request: URLRequest,
    user=Depends(get_current_user),
    _=Depends(get_api_key)
):
    return predict_phishing(request.url, request.model_name)


@router.post("/predict/manual")
def predict_manual(
    request: ManualFeatureRequest,
    user=Depends(get_current_user),
    _=Depends(get_api_key)
):
    return predict_manual_features(request.features, request.model_name)


@router.post("/predict/batch")
def predict_batch(
    file: UploadFile = File(...),
    model_name: str = "Random Forest",
    user=Depends(get_current_user),
    _=Depends(get_api_key)
):
    return predict_batch_csv(file, model_name)


@router.get("/model/evaluation")
def model_evaluation(
    model_name: str = "Random Forest",
    user=Depends(get_current_user),
    _=Depends(get_api_key)
):
    return evaluate_model(model_name)