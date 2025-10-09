from collections import defaultdict
from git import Repo
from pathlib import Path
import argparse
import difflib
import io
import json
import os
import regex as re
import sys

# TODO: To create requirements.txt
# pip freeze > requirements.txt
# Install dependencies in requirements.txt:
# pip install -r requirements.txt

# Bash input in command line:
# python ./git_scanning.py --repo <path|url> --n <commits> --out report.json


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

    # Extract all relevant commits, messages and diffs from repo
    if check_if_path(repo_link):
        repo = Repo(repo_link)
    else:
        cwd = Path.cwd()
        repo = Repo.clone_from(repo_link, cwd.parent / "New_Repo")

    # Debug: Print all selected commits to see what we're working with
    # Storing last n commits from all branches
    last_n_commits = repo.iter_commits(all=True, max_count=n)

    # Extracting the necessary information about each commit in advance
    hashes = [commit.hexsha for commit in last_n_commits]
    commit_messages = [commit.message for commit in last_n_commits]

    # TODO: Make sure there are no "out of range" errors!
    n_commit_list = list(repo.iter_commits(all=True))[:n]
    comp_commits = list(repo.iter_commits(all=True))[1:n+1]
    commit_pairs = list(zip(n_commit_list, comp_commits))

    diffs_to_parent = {a: b.diff(a) for a, b in commit_pairs}

    # TODO: Fix this part
    changed_files = []
    for idx, diff in enumerate(diffs_to_parent):
        files_in_commit = {}

        # Check the correctness of the diff file output
        change_types = ['A', 'M']
        changes_by_type = defaultdict(list)
        for change_type in change_types:
            changes_of_type = [item for item in diffs_to_parent[diff].iter_change_type(change_type)]
            changes_by_type[change_type].extend(changes_of_type)

        for diff_item in diffs_to_parent[diff].iter_change_type("A"):
            decoded_path = diff_item.a_rawpath.decode("utf-8")
            targetfile = diff.tree / decoded_path
            with io.BytesIO(targetfile.data_stream.read()) as f:
                files_in_commit[diff_item.a_rawpath] = f.read().decode("utf-8")
        for diff_item in diffs_to_parent[diff].iter_change_type("M"):
            if diff_item.a_blob is not None:
                files_in_commit[diff_item.a_rawpath] = diff_item.a_blob.data_stream.read().decode('utf-8')
        changed_files.append(files_in_commit)

    commit_dict = {hexsha: {"msg": message, "changed_files": files_in_commit} for hexsha, message, files_in_commit in zip(hashes, commit_messages, changed_files)}

    # TODO: Establish connection to Llama 3 without leaking token

    # TODO: Create a good prompt for finding issues

    # TODO: Add confidence calculation to predictions (built into Llama model?)

    # TODO: Additional layer of safety through entropy or regex

    # Save issues from dictionary to JSON file
    # Attributes for each issue: commit hash, file path, line/offset snippet, finding type, confidence
    json.dump(issue_dict, open(out, "w"), indent=4)


if __name__ == "__main__":
    # TODO: Make sure that the inputs provided by user cannot break the program (Error messages to catch cases and ask to try again?)
    # Parse all arguments entered in command line
    args = parser.parse_args(sys.argv[1:])
    threat_analysis(args.repo, args.n, args.out)
