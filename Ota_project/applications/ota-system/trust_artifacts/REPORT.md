# Initial OTA readiness model evaluation

Included 100 complete windowed attempts; excluded 134 legacy or failed attempts. Splits: {'train': 60, 'validation': 20, 'test': 20}. Model: depth-2 Gini decision tree.

Only pre-update runtime measurements enter the model. Scenario, version, attempt ID, outcome, post-update data, injection records and firmware hash are excluded from model inputs.

Held-out model accuracy: 100.0%; balanced accuracy: 100.0%. Rule-only held-out accuracy: 100.0%.

The model identifies nominal, slow-service, or unavailable-service conditions. Interrupted downloads are not predicted before their injection. The policy may defer updates on degradation, but these experiments do not establish that its install decisions improve safety.

- One device and one firmware; repeated runs are correlated and are not independent experimental sessions.
- Split is chronological within scenario, not a global prospective or independent-session evaluation.
- Labels describe controlled pre-update service conditions, not independently measured safe-install decisions.
- Interrupted-download pre-windows are labeled nominal: the future injected interruption is not observable yet.
- No compromise examples, cryptographic attack evaluation, memory-stress or weak-Wi-Fi validation.
- Legacy runs and failed attempts excluded from fitting; retained for separate analysis.
- Readiness thresholds are provisional engineering rules; no calibrated trust probability is claimed.
