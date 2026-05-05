from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.ids_agent import IDSAgent
from agents.anomaly_agent import AnomalyAgent
from agents.log_agent import LogAgent
from core.risk_fusion import RiskFusionEngine
from core.response_agent import ResponseAgent

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

# Load agents once
ids_agent     = IDSAgent()
anomaly_agent = AnomalyAgent()
log_agent     = LogAgent()
fusion        = RiskFusionEngine()
responder     = ResponseAgent()


def extract_features(log_text: str):
    features = []

    # basic features
    features.append(len(log_text))  # length
    features.append(sum(1 for c in log_text if c.isupper()))  # uppercase count
    features.append(sum(1 for c in log_text if c.isdigit()))  # digits

    keywords = ["ddos", "attack", "scan", "flood", "exploit"]
    features.append(sum(1 for k in keywords if k in log_text.lower()))

    # pad to 60 features
    while len(features) < 60:
        features.append(0.0)

    return features[:60]
class AttackEvent(BaseModel):
    label: str
    log_text: str


@app.post("/analyze")
def analyze(event: AttackEvent):

    # 🔥 generate features from log
    features = extract_features(event.log_text)

    # AI models
    ids_score     = ids_agent.predict(features)
    anomaly_score = anomaly_agent.predict(features)
    log_score     = log_agent.predict(event.log_text)

    # fusion
    final_score, risk_level = fusion.fuse(
        ids_score,
        anomaly_score,
        log_score
    )

    result = responder.act(final_score, risk_level)

    return {
        "label": event.label,
        "ids_score": round(ids_score, 3),
        "anomaly_score": round(anomaly_score, 3),
        "log_score": round(log_score, 3),
        "final_score": round(final_score, 3),
        "risk_level": risk_level,
        "action": result["action"],
    }