from huggingface_hub import login
import argparse
import json
import regex as re
import sys

# TODO: Make sure that the command line input functions similarly to example provided below
# git_screener.py --repo <path|url> --n <commits> --out report.json

# TODO: How can --repo recognize both file system paths and URLs? If-else statement?


# Initializing arguments that can be recognized by parser
parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=str, help="Git repository name", required=True)
parser.add_argument("--n", type=int, help="Number of commits to be scanned", required=True)
parser.add_argument("--out", type=str, help="Output json file name", default="report.json")

def threat_analysis(repo, n, out):
    # Create a dictionary to store issues found by Llama model (is a defaultdict needed?)
    issue_dict = {}

    # TODO: Extract all relevant commits, messages and diffs from repo

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
