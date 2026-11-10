# Decision experiments: from observations to workflow changes

The source project studies how an agent should read evidence, revise a candidate, obtain a decision and propagate accepted work. These choices share state: a useful review can become inapplicable after a revision, and an unchanged earlier objection can be forgotten by a later model response.

## Reproduce the extracted research kernels

```sh
python -B -m decision_lab.demo
python -B -m unittest discover -s tests -p 'test_decision_*.py' -v
```

The demo uses an original sensor-summary fixture. It prints a bounded policy search, a counterexample-to-revision replay, and a case where a later `ready` response cannot silently discard an earlier objection. It makes no model calls. Both implementation modules are preserved from the working research project; the example is a portable public adapter.

## 1. Plan over information available before an action

[`planning.py`](../decision_lab/planning.py) represents candidate versions, possible worlds, defect losses, scoped evidence, actions and stopping requirements. A finite AND/OR search explores conditional policies. Action outcomes include an explicit no-information branch; a failed or inconclusive check cannot masquerade as a risk reduction. Search limits report incomplete exploration rather than asserting optimality.

Planning input excludes the actual world, future observations and reference answers. `replay_decision_case` receives observations separately, allowing decisions to be inspected from their real preceding state. Evidence scope and source/condition versions govern applicability. Duplicate claims from one source add no independent confidence; revocation can reopen possibilities. An inconsistent evidence intersection remains a conflict.

The demo's counterexample raises the lower loss bound. Correcting the candidate changes its features, but stopping still waits for a version-matched approval and propagation to the consumer. Approval is responsibility, not semantic risk reduction. The finite model is an inspectable research prototype; its specified worlds and losses are assumptions, not an estimated population error rate.

## 2. Compare complete and partitioned model assessment

[`fusion.py`](../decision_lab/fusion.py) accepts either one full assessment or views partitioned by source meaning, rendering and applicability. Both pass through the same output contract and fusion logic. Exact citations are checked, repeated source content is deduplicated, missing dimensions and conflicting judgments remain visible, and an unsupported `ready` recommendation is blocked. Citation matching establishes the quoted span, not the truth of a semantic judgment.

In the source workflow, matched packets were used to compare the complete and parallel designs for error discovery, unresolved disagreement, latency and input cost. Observations showed a latency/input-cost tradeoff and exposed lost-objection cases. They motivate the implementation here; they do not establish that parallel review is generally more accurate. Private text, model transcripts and measured case records are not redistributed as public benchmark data.

## 3. Carry unresolved observations into the next decision

`check_observation_continuity` binds observations to the packet and preserves unresolved problems or unknowns. A later ordinary `ready` response does not resolve an earlier objection. A changed candidate or scope requires a local applicability judgment; closure needs an explicit, cited disposition targeting that observation and current packet. The continuity layer preserves disagreements for review without treating them as proven defects.

This is the concrete workflow improvement produced by the experiment: evaluate a new response in the context of prior unresolved evidence, then determine what still needs action. The versioned runtime provides the separate storage and recovery layer described in [its guide](versioned-runtime.md). The two modules remain independently callable; this release does not imply an automatic production policy controller.

## Useful inspection route

- `decision_lab/planning.py`: finite information state, evidence applicability, action effects, stop conditions and policy frontier.
- `decision_lab/fusion.py`: common assessment contract, citation checking, fusion and observation continuity.
- `decision_lab/demo.py`: original runnable example with separate planning and replay inputs.
- `tests/test_decision_planning.py`, `tests/test_decision_fusion.py`: retained counterexamples and regression cases.

The next experiment can alter model allocation or context selection while preserving the packet, unresolved observations and evaluation criteria. That makes architecture changes comparable without reducing the research question to process completion.
