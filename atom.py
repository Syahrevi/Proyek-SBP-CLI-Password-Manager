
import json
import os
import tempfile

def atomic_write(path, obj):
    dirpath = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirpath, prefix="dbtmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            json.dump(obj, tf, indent=4, ensure_ascii=False)
            tf.flush()
            os.fsync(tf.fileno())
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass