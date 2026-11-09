"""Body-free candidate capture commitments, not self-issued authorization."""
from source_adapter import canonical,sha

def capture_receipt(capture):
    return {'owner':capture['owner'],'origin_sha256':sha(canonical(capture['origin'])),
            'member_grant_sha256':sha(canonical(capture['member_grant'])),
            'archives':{k:{'sha256':sha(v),'bytes':len(v)} for k,v in capture['archives'].items()},
            'retained':[{'metadata_sha256':sha(canonical(x['metadata'])),'raw_sha256':sha(x['raw']),'raw_bytes':len(x['raw'])} for x in capture['retained']]}
