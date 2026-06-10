import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.ml_classifier import classify

print('=== MODEL ACCURACY TESTS ===')

r = classify([1.0, 1.0, 0.8, 1.0, 1.0, 0.3, 0.0])
status = 'PASS' if r['risk_score'] >= 60 else 'FAIL'
print(f"Phishing test:    score={r['risk_score']:3d}  {status}")

r = classify([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
status = 'PASS' if r['risk_score'] < 30 else 'FAIL'
print(f"Safe test:        score={r['risk_score']:3d}  {status}")

r = classify([0.3, 0.2, 0.0, 0.8, 1.0, 0.1, 0.0])
status = 'PASS' if r['risk_score'] >= 60 else 'CHECK'
print(f"Auth+imperson:    score={r['risk_score']:3d}  {status}")

r = classify([0.5, 0.3, 0.5, 0.4, 0.5, 0.2, 1.0])
status = 'PASS' if r['risk_score'] >= 80 else 'FAIL'
print(f"Known bad URL:    score={r['risk_score']:3d}  {status}")
