import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.tasks.training_tasks import retrain_model

org_id = '0f5e96c7-dc96-481d-9cbc-a6c44f7c31a5'
print('Retraining for org:', org_id)
print('This will take 5-10 minutes on ~18,000 samples...')

result = retrain_model.apply(args=[org_id]).get(timeout=900)

print('')
print('=== RETRAIN COMPLETE ===')
print('F1 before:    ', result.get('f1_before'))
print('F1 after:     ', result.get('f1_after'))
print('Model version:', result.get('model_version'))
