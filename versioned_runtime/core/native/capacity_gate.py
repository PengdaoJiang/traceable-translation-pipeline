"""Pure next-state capacity checks, not admission or publication authority.

The caller must hold its existing integrity epoch and authenticate the session or
perform genesis admission independently. Reading candidate objects may populate
Repo's operation-local buffers; no ref, intent, session, or registry is changed.
This module intentionally does not install global monkeypatches in v22.
"""
import copy


def preview_transition_state(k, session, plan):
    """Return exact next pending state without advancing a registered session."""
    delta = plan['delta']
    k.need(plan['parent'] == delta['parent'] == session.root,
           'capacity transition parent')
    k.need(plan['code'] == delta['code'] == session.code and
           plan['schema'] == delta['schema'] == session.schema,
           'capacity transition pins')
    k.delta_check(session, delta)
    # Validate the starting containers too; a next-state encoder must not repair
    # a malformed starting state by silently dropping key/value disagreement.
    before = k._pending_state(session)
    k._pending_contract(before, session.root)
    for key, value in session._active.items():
        k.need(key == (value['event'], value['target']),
               'capacity active dictionary key mismatch')
    active = dict(session._active)
    seen = set(session._seen)
    for event in delta['opened']:
        key = (event['event'], event['target'])
        k.need(key not in seen, 'duplicate obligation identity')
        seen.add(key)
        active[key] = event
    for event in delta['resolved']:
        key = (event['event'], event['target'])
        k.need(key in active and active[key] == event,
               'resolve exact active identity')
        del active[key]
    pending = {'format': 'root-bound-pending-state/v1',
               'root': plan['candidate'],
               'active': [copy.deepcopy(active[key]) for key in sorted(active)],
               'seen': [list(key) for key in sorted(seen)],
               'transitions': session.transitions + 1}
    k._pending_contract(pending, plan['candidate'])
    return pending


def encode_restart_envelope(k, r, context, candidate_commit, candidate_pending):
    """Encode the complete exact v22 envelope, including candidate root binding.

    context exposes admission/code/schema/origin_grant/origin_sha256. A genesis
    caller can supply an unregistered metadata-only context. This is sizing and
    validation only, and cannot register that context as an authenticated session.
    Export and prepublication checks should both use this encoder.
    """
    k._pending_contract(candidate_pending, candidate_commit)
    grant = context.origin_grant
    k._grant_contract(grant)
    k.need(context.origin_sha256 == grant['origin_sha256'],
           'capacity origin identity')
    pending = copy.deepcopy(candidate_pending)
    envelope = {
        'format': k.RESTART_FORMAT,
        'repository': k._repository_identity(r),
        'baseline': context.admission, 'root': candidate_commit,
        'code': context.code, 'schema': context.schema,
        'origin_grant': copy.deepcopy(grant),
        'origin_sha256': context.origin_sha256,
        'scope': k.scope_descriptor(grant),
        'root_binding': k._bounded_root_binding(r, candidate_commit, grant),
        'pending': pending, 'pending_sha256': k.sha(k.canonical(pending)),
        'pending_active_count': len(pending['active']),
        'pending_seen_count': len(pending['seen']),
        'trust_basis': 'PRIOR_FULL_ADMISSION_AND_VALID_DERIVATION_NOT_FRESH_FULL_AUDIT',
    }
    raw = k.canonical(envelope)
    k.need(len(raw) <= k.SCHEMA['restart']['checkpoint_bytes_max'],
           'restart checkpoint byte limit')
    return raw


def check_candidate_capacity(k, r, session, candidate_commit,
                             candidate_pending=None):
    """Check complete checkpoint capacity, returning the exact canonical bytes.

    If pending is omitted, session must already describe this exact candidate.
    No candidate root is silently substituted into existing pending state.
    """
    if candidate_pending is None:
        k.need(session.root == candidate_commit, 'capacity candidate state root')
        candidate_pending = k._pending_state(session)
    limits = k.SCHEMA.get('publication_capacity', {})
    if 'transitions_max' in limits:
        k.need(candidate_pending['transitions'] <= limits['transitions_max'],
               'publication transition count limit')
    return encode_restart_envelope(k, r, session, candidate_commit,
                                   candidate_pending)


def check_plan_capacity(k, r, session, plan):
    """Call immediately after reconstruction and before intent/ref publication."""
    pending = preview_transition_state(k, session, plan)
    message = k.canonical(plan['delta'])
    k.need(plan['message'].encode('utf-8') == message,
           'capacity exact canonical transition log')
    k.need(len(message) <= k.SCHEMA['pending']['log_bytes'],
           'transition log byte limit')
    expected = k.commit_bytes(plan['tree'], plan['parent'], plan['message'])
    k.need(len(expected) <= 66560, 'commit log byte limit')
    actual = r.get(plan['candidate'], 'commit', 'capacity_candidate')
    k.need(actual == expected, 'capacity candidate commit identity')
    # Intent and replay ceilings, if a versioned run contract declares them,
    # are independent of the existing transition/checkpoint format limits.
    limits = k.SCHEMA.get('publication_capacity', {})
    if 'intent_bytes_max' in limits:
        k.need(len(k.canonical(plan)) <= limits['intent_bytes_max'],
               'publication intent byte limit')
    if 'transitions_max' in limits:
        k.need(pending['transitions'] <= limits['transitions_max'],
               'publication transition count limit')
    return check_candidate_capacity(k, r, session, plan['candidate'], pending)
