"""ML classifier service (Section 5.1 Task 3, Section 8).

Provides a process-scoped cached model loader and a classify() function that
maps a 7-element feature vector to a risk_score (0-100) and severity band.

Feature vector FIXED order (must match ml/train.py and the classify_email task):
    [urgency_language, credential_request, link_mismatch,
     impersonation_language, auth_failure, grammar_quality, known_bad_url]

The model is an sklearn Pipeline (StandardScaler + RandomForestClassifier)
serialised with joblib.  It is loaded once per worker process via
``functools.lru_cache`` and cached thereafter.

If the model file is absent (e.g. during first deploy before ``ml/train.py``
runs), ``classify()`` raises :class:`ModelNotFoundError`.  The ``classify_email``
Celery task catches this and schedules a retry with countdown=30.
"""
from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Any

import joblib
import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Model path resolution
# ---------------------------------------------------------------------------

# Default: <repo-root>/backend/ml/model.pkl
_DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "ml" / "model.pkl"

# Allow test / container override via environment variable
_MODEL_PATH: Path = Path(os.environ["PHISHGUARD_MODEL_PATH"]) if "PHISHGUARD_MODEL_PATH" in os.environ else _DEFAULT_MODEL_PATH


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


# Re-export from canonical location so existing imports remain unbroken.
from app.core.exceptions import ModelNotFoundError  # noqa: F401, E402


# ---------------------------------------------------------------------------
# Model loader (process-scope cache)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def get_model() -> Any:
    """Load and cache the sklearn Pipeline from ml/model.pkl.

    The result is cached indefinitely for the lifetime of the worker process.
    To pick up a newly trained model without restarting the worker, call
    ``get_model.cache_clear()`` before the next ``classify()`` call.

    Returns:
        The sklearn Pipeline (StandardScaler + RandomForestClassifier).

    Raises:
        ModelNotFoundError: If ml/model.pkl does not exist at
            :data:`_MODEL_PATH`.
    """
    if not _MODEL_PATH.exists():
        raise ModelNotFoundError(
            f"Model not found at '{_MODEL_PATH}'. "
            "Run 'cd backend && python ml/train.py' to generate it."
        )
    model = joblib.load(_MODEL_PATH)
    log.info("ml_model_loaded", path=str(_MODEL_PATH))
    return model


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify(feature_vector: list[float]) -> dict[str, Any]:
    """Run the classifier and return risk_score + severity.

    The risk_score is the phishing class probability scaled to [0, 100].
    Threshold-based classification into 'safe' / 'suspicious' / 'phishing'
    is applied by the ``classify_email`` Celery task using the organisation's
    current thresholds — this function only returns the raw numeric score.

    Args:
        feature_vector: 7-element list of floats in the fixed order defined
            in :mod:`ml.train`.  Each value is normalised to [0.0, 1.0].

    Returns:
        Dictionary with keys:

        - ``risk_score`` (int): 0-100 phishing probability score.
        - ``severity`` (str): ``'critical'`` | ``'high'`` | ``'medium'`` |
          ``'low'`` — derived from risk_score using the same thresholds as
          :func:`~app.routers.emails._severity`.

    Raises:
        ModelNotFoundError: Propagated from :func:`get_model` when the model
            file is absent.
        ValueError: If *feature_vector* does not contain exactly 7 elements.
    """
    if len(feature_vector) != 7:
        raise ValueError(
            f"feature_vector must have exactly 7 elements, got {len(feature_vector)}"
        )

    clf = get_model()
    classes: list[str] = list(clf.classes_)

    proba = clf.predict_proba([feature_vector])[0]
    phishing_idx = classes.index("phishing") if "phishing" in classes else 0
    phishing_prob = float(proba[phishing_idx])

    risk_score = max(0, min(100, int(round(phishing_prob * 100))))

    if risk_score >= 90:
        severity = "critical"
    elif risk_score >= 80:
        severity = "high"
    elif risk_score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return {"risk_score": risk_score, "severity": severity}
