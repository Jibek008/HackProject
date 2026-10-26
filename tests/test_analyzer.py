"""Тесты анализатора: детекция сигналов инъекции и разбор SQL."""

import pytest

from lab import analyzer


# --- Сегментация -------------------------------------------------------------
def test_segments_contain_code_and_input():
    segments = analyzer.build_segments(
        analyzer.VULNERABLE_TEMPLATE,
        {"username": "bob", "password": "pw"},
    )
    kinds = [s["kind"] for s in segments]
    assert kinds.count("input") == 2
    assert kinds.count("code") == 3
    inputs = [s for s in segments if s["kind"] == "input"]
    assert inputs[0]["field"] == "username"
    assert inputs[0]["text"] == "bob"
    assert inputs[0]["length"] == 3


def test_segments_reconstruct_original_query():
    username = "bob"
    password = "pw"
    segments = analyzer.build_segments(
        analyzer.VULNERABLE_TEMPLATE,
        {"username": username, "password": password},
    )
    rebuilt = "".join(s["text"] for s in segments)
    assert rebuilt == analyzer.VULNERABLE_TEMPLATE.format(
        username=username, password=password
    )


def test_secure_segments_use_placeholders():
    segments = analyzer.build_secure_segments("bob", "pw")
    assert [s["kind"] for s in segments if s["kind"] == "param"] == [
        "param",
        "param",
    ]
    params = [s for s in segments if s["kind"] == "param"]
    assert params[0]["text"] == "?"
    assert params[0]["value"] == "bob"


# --- Детекция сигналов -------------------------------------------------------
def test_plain_input_has_no_signals():
    assert analyzer.detect_signals("student") == []
    assert analyzer.detect_signals("lab_pass_123") == []


def test_quote_terminator_detected():
    signals = analyzer.detect_signals("oops'")
    ids = {s["id"] for s in signals}
    assert "quote_terminator" in ids
    assert signals[0]["severity"] in ("high", "critical")


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "' or 'a'='a",
        "x' OR '1'='1",
    ],
)
def test_tautology_detected(payload):
    ids = {s["id"] for s in analyzer.detect_signals(payload)}
    assert "tautology" in ids


@pytest.mark.parametrize("payload", ["' --", "' #", "x' /*"])
def test_comment_detected(payload):
    ids = {s["id"] for s in analyzer.detect_signals(payload)}
    assert "comment" in ids


def test_union_detected():
    ids = {s["id"] for s in analyzer.detect_signals("' UNION SELECT id, owner, content FROM secrets --")}
    assert "union_select" in ids


def test_data_exfiltration_detected():
    signals = analyzer.detect_signals("' UNION SELECT id, owner, content FROM secrets --")
    ids = {s["id"] for s in signals}
    assert "data_exfiltration" in ids
    exfil = [s for s in signals if s["id"] == "data_exfiltration"][0]
    assert exfil["severity"] == "critical"


def test_schema_disclosure_detected():
    ids = {s["id"] for s in analyzer.detect_signals("' UNION SELECT id, name, sql FROM sqlite_master --")}
    assert "schema_disclosure" in ids


def test_boolean_blind_detected():
    ids = {
        s["id"]
        for s in analyzer.detect_signals(
            "' OR SUBSTR((SELECT content FROM secrets LIMIT 1),1,1)='F' --"
        )
    }
    assert "boolean_blind" in ids


def test_time_based_detected():
    ids = {s["id"] for s in analyzer.detect_signals("' AND length(randomblob(20000000)) > 0 --")}
    assert "time_based" in ids


def test_stacked_query_detected():
    ids = {s["id"] for s in analyzer.detect_signals("'; SELECT * FROM secrets --")}
    assert "stacked_query" in ids


def test_signals_sorted_by_severity():
    signals = analyzer.detect_signals("' OR '1'='1' --")
    severities = [analyzer.SEVERITY_ORDER[s["severity"]] for s in signals]
    assert severities == sorted(severities, reverse=True)


def test_signal_has_explanation():
    for s in analyzer.detect_signals("' OR '1'='1' --"):
        assert s["title"]
        assert len(s["detail"]) > 30
        assert s["severity"] in analyzer.SEVERITY_ORDER


# --- Вердикты ----------------------------------------------------------------
def test_verdict_safe_for_plain_input():
    result = analyzer.analyze("student", "lab_pass_123")
    assert result["verdict"] == "safe"
    assert result["signal_count"] == 0
    assert result["max_severity"] == "none"


def test_verdict_dangerous_for_injection():
    result = analyzer.analyze("' OR '1'='1' --", "x")
    assert result["verdict"] == "dangerous"
    assert result["signal_count"] >= 3


def test_parameterized_summary_explains_neutralization():
    result = analyzer.analyze("' OR '1'='1' --", "x", parameterized=True)
    assert result["parameterized"] is True
    assert result["signals"], "сигналы во вводе остаются"
    assert "параметризован" in result["summary"].lower()


def test_parameterized_summary_for_clean_input():
    result = analyzer.analyze("student", "lab_pass_123", parameterized=True)
    assert result["verdict"] == "safe"
    assert "параметр" in result["summary"].lower()


def test_analyze_merges_both_fields():
    result = analyzer.analyze("plain", "' OR '1'='1' --")
    fields = {s.get("id") for s in result["signals"]}
    assert "tautology" in fields


# --- Объяснение результата ---------------------------------------------------
def test_explain_outcome_mentions_bypass():
    text = analyzer.explain_outcome("vulnerable", 3, True, True)
    assert "обойдена" in text.lower()


def test_explain_outcome_mentions_no_match():
    text = analyzer.explain_outcome("secure", 0, False, False)
    assert "не соответствуют" in text.lower()
