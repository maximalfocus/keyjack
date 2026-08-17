"""The integrated comparison run — the scenario engine, driven directly (no terminal input)."""

from __future__ import annotations

from keyjack.attacker.compare import run_comparison


def test_comparison_covers_every_sink_and_secure_stays_unchanged(
    base_url: str, vuln_base_url: str, halffixed_base_url: str
) -> None:
    comparison = run_comparison(base_url, vuln_base_url, halffixed_base_url)

    sinks = {(row.sink, row.app) for row in comparison.rows}
    assert ("embedded signing key", "vulnerable") in sinks
    assert ("client-computed verdict", "vulnerable") in sinks
    assert ("client-hashed credential", "vulnerable") in sinks
    assert ("weak pickup code", "vulnerable") in sinks
    assert ("embedded signing key", "half-fixed") in sinks
    assert ("client-computed verdict", "half-fixed") in sinks

    # Every attack lands against the vulnerable/half-fixed apps...
    assert comparison.all_vulnerable_accepted
    # ...and the secure app's settled state is unchanged by every identical request.
    assert comparison.all_secure_unchanged


def test_comparison_output_shows_every_column(
    base_url: str, vuln_base_url: str, halffixed_base_url: str
) -> None:
    rendered = run_comparison(base_url, vuln_base_url, halffixed_base_url).render()
    for column in (
        "extracted:",
        "from:",
        "request:",
        "authority used:",
        "vulnerable app:",
        "secure app:",
        "secure settled/inventory unchanged:",
    ):
        assert column in rendered
