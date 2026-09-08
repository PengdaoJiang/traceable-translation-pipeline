# Three decisions behind the pipeline

## Display numbers are evidence, not primary keys

The original text includes repeated chapter numbers and headings that cover a range. Renumbering them would hide a source fact. The pipeline assigns sequential `SU-*` units and paragraph IDs while preserving declared chapter numbers, occurrence numbers and range boundaries. Coverage and an ordered structure signature detect a changed topology.

The public authored fixture reproduces those structural shapes with unrelated short text. Its expected structure is declared independently, not learned from whatever the parser happens to emit.

## Preserve the baseline; apply an explicit correction layer

Each approved patch names a baseline hash, issue and exact location/content. Line-anchored corrections run before ordered global replacements. Duplicate anchors, unexpected occurrence counts and forward dependencies fail rather than modifying an uncertain location. Diplomatic and critical text remain available together.

The demo changes a typo only in the generated reading layer. The baseline hash is checked before and after. This verifies mechanics, not that an arbitrary editorial correction is semantically right.

## Review the version that was actually produced

The producer, reviewer and adjudicator have distinct outputs linked by hashes. A changed dossier, incorrect stage, shared task identity or changed subject invalidates the dependent chain. No score or checklist can replace the substantive readable review; the validator only checks the records and their relationship.

The public tests exercise both a valid synthetic chain and negative mutations. They do not attest that separate people or model tasks reviewed the demo.
