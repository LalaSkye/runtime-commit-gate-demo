"""
Extension test: double approval.
"""

import pytest


@pytest.mark.xfail(reason="Double-approval extension not implemented yet")
def test_double_approval_required_for_sensitive_action():
    """
    Sensitive actions should require two valid decision records
    from different actors.
    """
    assert False
