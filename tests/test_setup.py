"""Smoke tests: confirm the project foundation is wired up correctly."""

import cloudtrail_mapper


def test_package_imports():
    # If this line runs, Python found the package in src/ via the editable install.
    assert cloudtrail_mapper is not None


def test_package_has_version():
    assert cloudtrail_mapper.__version__ == "0.1.0"
