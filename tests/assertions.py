"""Shared assertions for the shipped conformance gate."""


def assert_structural_failure(problems: list[str], reason: str) -> None:
    """Require one normalization failure with the expected refusal reason."""
    assert len(problems) == 1, problems
    problem = problems[0]
    assert problem.startswith("structural: normalizer failed:"), problems
    assert reason in problem, problems
