import os, sys, email as emaillib, argparse, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.database import get_sync_engine
from app.models.training_sample import TrainingSample
from sqlalchemy.orm import Session

def import_folder(folder_path, label, org_id, limit=None):
    engine = get_sync_engine()
    folder = Path(folder_path)
    files = [f for f in folder.iterdir()
             if f.is_file() and not f.name.startswith('.')]
    if limit:
        files = files[:limit]

    print(f"Importing {len(files)} files as '{label}' from {folder_path}")
    added = 0
    skipped = 0

    with Session(engine) as db:
        for i, filepath in enumerate(files):
            if i % 200 == 0 and i > 0:
                db.commit()
                print(f"  {i}/{len(files)} — {added} added so far")
            try:
                with open(filepath, 'rb') as f:
                    raw = f.read()

                # Try parsing as MIME email first
                msg = emaillib.message_from_bytes(raw)
                body_text = ''

                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == 'text/plain':
                            try:
                                chunk = part.get_payload(decode=True)
                                if chunk:
                                    body_text += chunk.decode(
                                        'utf-8', errors='replace'
                                    )
                            except Exception:
                                pass
                else:
                    try:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode(
                                'utf-8', errors='replace'
                            )
                    except Exception:
                        body_text = str(msg.get_payload() or '')

                # Fallback: if MIME parsing gave no body,
                # read the file as plain text directly
                # (handles Enron .txt files and similar)
                if not body_text.strip():
                    body_text = raw.decode('utf-8', errors='replace')

                body_text = body_text.strip()

                if len(body_text) < 10:
                    skipped += 1
                    continue

                sample = TrainingSample(
                    org_id=uuid.UUID(org_id),
                    body_text=body_text[:100000],
                    label=label,
                    source='eml_upload',
                )
                db.add(sample)
                added += 1

            except Exception as e:
                skipped += 1
                continue

        db.commit()

    print(f"Complete: {added} added, {skipped} skipped")
    return added

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('folder')
    parser.add_argument('label', choices=['phishing','safe'])
    parser.add_argument('org_id')
    parser.add_argument('--limit', type=int, default=None)
    args = parser.parse_args()
    import_folder(args.folder, args.label, args.org_id, args.limit)
