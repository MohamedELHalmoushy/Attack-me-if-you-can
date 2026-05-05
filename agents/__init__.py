"""
agents/ — Four specialized AI agents for cyber threat detection.

Each agent follows the same interface:
    agent.predict(input_data) -> float   # 0.0 = safe, 1.0 = attack
"""

from agents.ids_agent import IDSAgent
from agents.anomaly_agent import AnomalyAgent
from agents.log_agent import LogAgent
from agents.base_agent import BaseAgent

__all__ = ["BaseAgent", "IDSAgent", "AnomalyAgent", "LogAgent"]
