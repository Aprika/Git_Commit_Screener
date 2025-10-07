import pytest
from git_scanning import check_if_path, threat_analysis
from pathlib import Path, PureWindowsPath

# Setup using GitHub page from GitPython Quick Start
@pytest.fixture
def setup_data():
    # Setup connection to GitHub repo to test on
    cwd = Path.cwd()
    repo_path = cwd.parents[1]
    repo_url = "https://github.com/gitpython-developers/QuickStartTutorialFiles.git"
    yield repo_path



def test_commit_access_path(setup_data):
    repo_path = setup_data
    threat_analysis(repo_path, 3, "report.json")
    assert True

"""
def test_commit_access_url(setup_data):
    repo_url = setup_data
    threat_analysis(repo_url, 3, "report.json")
    assert True
"""

