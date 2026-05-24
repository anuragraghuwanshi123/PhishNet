from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from app.api import routes_auth, routes_predict
from app.middleware.logging_middleware import LoggingMiddleware
from app.core.exceptions import register_exception_handlers
from fastapi.staticfiles import StaticFiles
import os

app = FastAPI(title='PhishNet - Phishing Detection API')

app.mount(
    "/reports",
    StaticFiles(directory="reports"),
    name="reports"
)

# link middleware
app.add_middleware(LoggingMiddleware)

# health endpoint
@app.get('/')
def root():
    return {'message': 'PhishNet API is running'}

# link endpoints
app.include_router(routes_auth.router, prefix='/auth', tags=['Auth']) # it shows authentication section in api
app.include_router(routes_predict.router, tags=['Prediction']) # it shows main prediction section in api

# CORS (allows React dashboard to connect) 
app.add_middleware( CORSMiddleware,
                    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], )

# monitoring using Prometheus
Instrumentator().instrument(app).expose(app)

# add exception handler
register_exception_handlers(app)