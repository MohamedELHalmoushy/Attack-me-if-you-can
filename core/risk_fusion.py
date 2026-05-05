import os
import logging
from dataclasses import dataclass
from typing import Tuple


logger = logging.getLogger(__name__)


@dataclass
class FusionResult:
    ids_score:     float
    anomaly_score: float
    log_score:     float
    weighted_score: float
    final_score:   float
    risk_level:    str
    rule_triggered: str   # which smart rule (if any) changed the score


class RiskFusionEngine:
    # Default weights
    WEIGHTS = {
        "ids":     float(os.getenv("WEIGHT_IDS",     "0.50")),
        "anomaly": float(os.getenv("WEIGHT_ANOMALY", "0.30")),
        "log":     float(os.getenv("WEIGHT_LOG",     "0.20")),
    }

    # Risk level thresholds
    THRESHOLDS = {
        "critical": float(os.getenv("RISK_THRESHOLD_CRITICAL", "0.85")),
        "high":     float(os.getenv("RISK_THRESHOLD_HIGH",     "0.65")),
        "medium":   float(os.getenv("RISK_THRESHOLD_MEDIUM",   "0.40")),
    }

    def fuse(
        self,
        ids_score: float,
        anomaly_score: float,
        log_score: float,
    ) -> Tuple[float, str]:
        result = self.fuse_detailed(ids_score, anomaly_score, log_score)
        return result.final_score, result.risk_level

    def fuse_detailed(
        self,
        ids_score: float,
        anomaly_score: float,
        log_score: float,
    ) -> FusionResult:

        weighted = (
            ids_score     * self.WEIGHTS["ids"]     +
            anomaly_score * self.WEIGHTS["anomaly"] +
            log_score     * self.WEIGHTS["log"]
        )
        final   = weighted
        rule    = "none"



        # Rule 1 — Zero-day / unknown attack
        # IDS doesn't recognise it (low score) but Anomaly does (high score)
        if ids_score < 0.30 and anomaly_score > 0.70:
            forced = max(final, 0.70)
            if forced > final:
                rule  = "zero-day: IDS LOW + Anomaly HIGH → forced HIGH"
                final = forced
                logger.info(f"Rule 1 triggered: {rule}")

        # Rule 2 — Confirmed coordinated attack (all three agree)
        if ids_score > 0.80 and anomaly_score > 0.80 and log_score > 0.80:
            forced = max(final, 0.88)
            if forced > final:
                rule  = "confirmed: all agents HIGH → forced CRITICAL"
                final = forced
                logger.info(f"Rule 2 triggered: {rule}")

        # Rule 3 — False positive suppression
        # IDS fires but behaviour is totally normal per Anomaly
        if ids_score > 0.70 and anomaly_score < 0.20:
            capped = min(final, 0.64)
            if capped < final:
                rule  = "fp-suppress: IDS HIGH + Anomaly LOW → capped MEDIUM"
                final = capped
                logger.info(f"Rule 3 triggered: {rule}")
                
        risk_level = self._score_to_level(final)

        logger.debug(
            f"Fusion: IDS={ids_score:.3f} "
            f"Anomaly={anomaly_score:.3f} "
            f"Log={log_score:.3f} "
            f"→ weighted={weighted:.3f} "
            f"→ final={final:.3f} "
            f"→ {risk_level}"
        )

        return FusionResult(
            ids_score=round(ids_score, 4),
            anomaly_score=round(anomaly_score, 4),
            log_score=round(log_score, 4),
            weighted_score=round(weighted, 4),
            final_score=round(final, 4),
            risk_level=risk_level,
            rule_triggered=rule,
        )

    def _score_to_level(self, score: float) -> str:
        if   score >= self.THRESHOLDS["critical"]: return "CRITICAL"
        elif score >= self.THRESHOLDS["high"]:     return "HIGH"
        elif score >= self.THRESHOLDS["medium"]:   return "MEDIUM"
        else:                                       return "LOW"

    def explain(self, ids: float, anomaly: float, log: float) -> str:
        """
        Return a human-readable explanation of a fusion decision.
        Useful for dashboard tooltips and reports.
        """
        r = self.fuse_detailed(ids, anomaly, log)
        lines = [
            f"Risk Level : {r.risk_level}",
            f"Final Score: {r.final_score:.3f}",
            "",
            "Agent Contributions:",
            f"  IDS     {r.ids_score:.3f}  × 0.50 = {r.ids_score * 0.50:.3f}",
            f"  Anomaly {r.anomaly_score:.3f}  × 0.30 = {r.anomaly_score * 0.30:.3f}",
            f"  Log     {r.log_score:.3f}  × 0.20 = {r.log_score * 0.20:.3f}",
            f"  Weighted sum = {r.weighted_score:.3f}",
        ]
        if r.rule_triggered != "none":
            lines += ["", f"Smart Rule: {r.rule_triggered}"]
        return "\n".join(lines)
