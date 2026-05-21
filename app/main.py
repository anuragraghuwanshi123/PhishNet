from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator
from app.api import routes_auth, routes_predict
from app.middleware.logging_middleware import LoggingMiddleware
from app.core.exceptions import register_exception_handlers

app = FastAPI(title='PhishNet - Phishing Detection API')

# link middleware
app.add_middleware(LoggingMiddleware)

# health endpoint
@app.get('/')
def root():
    return {'message': 'PhishNet API is running'}

# link endpoints
app.include_router(routes_auth.router, prefix='/auth', tags=['Auth'])
app.include_router(routes_predict.router, tags=['Prediction'])

# monitoring using Prometheus
Instrumentator().instrument(app).expose(app)

# add exception handler
register_exception_handlers(app)