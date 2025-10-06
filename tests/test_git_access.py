import pytest
from git_scanning import check_if_path, threat_analysis

# Setup using GitHub page from GitPython Quick Start
@pytest.fixture
def setup_data():
    # Setup connection to GitHub repo to test on
    repo_url = "https://github.com/gitpython-developers/QuickStartTutorialFiles.git"
    yield repo_url


def test_commit_access(setup_data):
    repo_url = setup_data
    threat_analysis(repo_url, 3, "report.json")
    assert True
