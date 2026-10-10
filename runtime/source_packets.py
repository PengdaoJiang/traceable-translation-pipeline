"""Read-only anchored packets, with no literary judgments or acceptance writes."""
import hashlib,json,sqlite3
from pathlib import Path

def connect(database):
    path=Path(database).resolve(strict=True)
    c=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
    c.execute('PRAGMA query_only=ON');c.row_factory=sqlite3.Row
    return c

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()

def packet(c, start, end):
    units = [dict(r) for r in c.execute('SELECT * FROM units WHERE ordinal BETWEEN ? AND ? ORDER BY ordinal', (start,end))]
    rows = [dict(r) for r in c.execute('SELECT p.* FROM paragraphs p JOIN units u USING(unit_id) WHERE u.ordinal BETWEEN ? AND ? ORDER BY char_start', (start,end))]
    return {'units': units, 'paragraph_count': len(rows), 'characters': sum(len(r['text']) for r in rows), 'paragraphs': rows}

def render(p):
    return '\n'.join([json.dumps({k:v for k,v in p.items() if k != 'paragraphs'},ensure_ascii=False)] + [r['paragraph_id']+' '+r['text'] for r in p['paragraphs']])+'\n'
