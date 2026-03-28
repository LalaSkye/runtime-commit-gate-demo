"""
Entry condition guard tests.

C1: condition present
C2: condition testable (not prose)
C3: condition bound to execution
C4: evaluation context declared
"""

from src.entry_guard import validate_entry


# ── C1: CONDITION_PRESENT ──

def test_missing_condition_holds():
    """No condition field -> HOLD."""
    result = validate_entry({"action": "deploy"})
    assert not result.passed
    assert result.failed_check == "C1_CONDITION_PRESENT"


def test_empty_condition_holds():
    """Empty condition -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "",
    })
    assert not result.passed
    assert result.failed_check == "C1_CONDITION_PRESENT"


# ── C2: CONDITION_TESTABLE ──

def test_prose_condition_holds():
    """Free prose test -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "looks good",
        "test": "seems safe",
        "binding": {"on_true": "pass_to_next_stage", "on_false": "hold"},
    })
    assert not result.passed
    assert result.failed_check == "C2_CONDITION_TESTABLE"


def test_missing_test_holds():
    """No test field -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window active",
    })
    assert not result.passed
    assert result.failed_check == "C2_CONDITION_TESTABLE"


def test_structured_test_missing_returns_holds():
    """Structured test without returns=boolean -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window active",
        "test": {"expr": "x == true"},
        "binding": {"on_false": "hold"},
    })
    assert not result.passed
    assert result.failed_check == "C2_CONDITION_TESTABLE"


def test_structured_test_missing_expr_holds():
    """Structured test without expr or predicate -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window active",
        "test": {"returns": "boolean"},
        "binding": {"on_false": "hold"},
    })
    assert not result.passed
    assert result.failed_check == "C2_CONDITION_TESTABLE"


# ── C3: CONDITION_BOUND ──

def test_missing_binding_holds():
    """No binding field -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window active",
        "test": {"expr": "x == true", "returns": "boolean", "context": ["x"]},
    })
    assert not result.passed
    assert result.failed_check == "C3_CONDITION_BOUND"


def test_binding_missing_on_false_holds():
    """Binding without on_false -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window active",
        "test": {"expr": "x == true", "returns": "boolean", "context": ["x"]},
        "binding": {"on_true": "pass_to_next_stage"},
    })
    assert not result.passed
    assert result.failed_check == "C3_CONDITION_BOUND"


def test_binding_on_false_not_hold_holds():
    """Binding with on_false != 'hold' -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window active",
        "test": {"expr": "x == true", "returns": "boolean", "context": ["x"]},
        "binding": {"on_false": "allow_anyway"},
    })
    assert not result.passed
    assert result.failed_check == "C3_CONDITION_BOUND"


# ── C4: EVALUATION_CONTEXT_BOUND ──

def test_undeclared_context_holds():
    """Expression references undeclared variable -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "deployment window active",
        "test": {
            "expr": "system_time_in_window == true",
            "returns": "boolean",
            "context": [],
        },
        "binding": {"gate": "condition", "on_false": "hold"},
    })
    assert not result.passed
    assert result.failed_check == "C4_EVALUATION_CONTEXT_BOUND"
    assert "system_time_in_window" in result.reason


def test_partial_context_holds():
    """Some variables declared, some not -> HOLD."""
    result = validate_entry({
        "action": "deploy",
        "condition": "deployment window active",
        "test": {
            "expr": "system_time >= window_start && system_time <= window_end",
            "returns": "boolean",
            "context": ["system_time", "window_start"],
        },
        "binding": {"on_false": "hold"},
    })
    assert not result.passed
    assert result.failed_check == "C4_EVALUATION_CONTEXT_BOUND"
    assert "window_end" in result.reason


# ── PASS ──

def test_valid_packet_passes():
    """All checks satisfied -> PASS."""
    result = validate_entry({
        "action": "deploy",
        "condition": "deployment window active",
        "test": {
            "expr": "system_time >= window_start && system_time <= window_end",
            "returns": "boolean",
            "context": ["system_time", "window_start", "window_end"],
        },
        "binding": {
            "gate": "condition",
            "on_true": "pass_to_next_stage",
            "on_false": "hold",
            "on_unevaluable": "hold",
        },
    })
    assert result.passed
    assert result.failed_check is None


def test_predicate_ref_passes():
    """Predicate reference as test string -> PASS."""
    result = validate_entry({
        "action": "deploy",
        "condition": "window check",
        "test": "window_active",
        "binding": {"on_true": "pass_to_next_stage", "on_false": "hold"},
    })
    assert result.passed
