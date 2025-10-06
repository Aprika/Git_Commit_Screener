from git import Repo
from huggingface_hub import login
from pathlib import PurePath, PureWindowsPath
import argparse
import json
import os

import regex as re
import sys

# TODO: To create requirements.txt
# pip freeze > requirements.txt
# Install dependencies in requirements.txt:
# pip install -r requirements.txt

# TODO: Make sure that the command line input functions similarly to example provided below
# git_screener.py --repo <path|url> --n <commits> --out report.json


# Initializing arguments that can be recognized by parser
parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=str, help="Git repository name", required=True)
parser.add_argument("--n", type=int, help="Number of commits to be scanned", required=True)
parser.add_argument("--out", type=str, help="Output json file name", default="report.json")

def check_if_path(repo_string):
    # Use RegEx to check if link is a local path (else assumes URL)
    if os.path.exists(os.path.dirname(repo_string)):
        return True
    else:
        return False



def threat_analysis(repo_link, n, out):
    # Create a dictionary to store issues found by Llama model (is a defaultdict needed?)
    issue_dict = {}

    # TODO: Extract all relevant commits, messages and diffs from repo
    if check_if_path(repo_link):
        repo = Repo(repo_link)
    else:
        # TODO: Add if/else to handle path types of different operating systems
        repo = Repo.clone_from(repo_link, PureWindowsPath(os.path.dirname(os.getcwd()), "New_Repo"))

    # Debug: Print all selected commits to see what we're working with
    print(repo.head)
    print(repo.tags)

    # TODO: Create a good prompt for finding issues (Llama Guard maybe?)

    # TODO: Establish connection to Llama 3 without leaking token

    # TODO: Additional layer of safety through entropy or regex

    # TODO: Add confidence calculation to predictions (built into Llama model?)

    # Save issues from dictionary to JSON file
    # Attributes for each issue: commit hash, file path, line/offset snippet, finding type, confidence
    json.dump(issue_dict, open(out, "w"), indent=4)


if __name__ == "__main__":
    # TODO: Make sure that the inputs provided by user cannot break the program (Error messages to catch cases and ask to try again?)
    # Parse all arguments entered in command line
    repo_name, num, output_file = parser.parse_args(sys.argv[1:])
    threat_analysis(repo_name, num, output_file)
