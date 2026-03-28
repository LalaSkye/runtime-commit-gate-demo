"""
Extension test: double approval.

XFAIL_CLASS: DEFERRED_FEATURE
Reason: Double-approval is a designed extension point, not a gap.
Status: Scaffold only. Implementation deferred to v0.2.
"""

import pytest


@pytest.mark.xfail(reason="DEFERRED_FEATURE: double-approval not implemented (v0.2)")
def test_double_approval_required_for_sensitive_action():
    """Two valid decision records from different actors required."""
    assert False
