def test_codeowners_uses_last_matching_rule_and_ignores_comments() -> None:
    from app.services.codeowners import owners_for_path

    source = """# default\n* @platform\n/services/payments/** @payments @security\n/services/** @backend\n"""

    assert owners_for_path(source, "services/payments/api.py") == ("@backend",)
    assert owners_for_path(source, "docs/readme.md") == ("@platform",)


def test_codeowners_directory_pattern_matches_descendants() -> None:
    from app.services.codeowners import owners_for_path

    assert owners_for_path("/infra/ @cloud\n", "infra/terraform/main.tf") == ("@cloud",)
