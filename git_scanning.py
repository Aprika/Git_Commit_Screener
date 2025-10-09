from chardet.universaldetector import UniversalDetector
from collections import defaultdict
from datetime import date
from git import Repo
from pathlib import Path
from transformers import AutoTokenizer
from vllm import LLM, SamplingParams
import argparse
import difflib
import io
import json
import os
import regex as re
import sys
import torch

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

def llama_prompting(input_data):
    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

    # You need a connection token for Llama 3 (gated model)
    # Login with access token using $ hf auth login
    directory = "/mounts/data/corp/huggingface/"
    model_name = "meta-llama/Llama-3.1-8B-Instruct"
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    # Create an LLM instance
    llm = LLM(dtype="half",
    model = model_name,
    tokenizer= model_name,
    download_dir=directory,
    gpu_memory_utilization=0.9,
    tensor_parallel_size=4,
    max_num_seqs=100,
    max_model_len=1500
    )

    # Prompt template definition
    # Attributes for each issue: commit hash, file path, line/offset snippet, finding type, confidence
    prompt_template = ("""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

Environment: ipython
Cutting Knowledge Date: December 2023

You are an expert in composing functions. You are given a question and a set of possible functions.
Based on the question, you will need to make one or more function/tool calls to achieve the purpose.
If none of the function can be used, point it out. If the given question lacks the parameters required by the function,

If you decide to invoke any of the function(s), you MUST put it in the format of [func_name1(params_name1=params_value1, params_name2=params_value2...), func_name2(params)]
You SHOULD NOT include any other text in the response.

Here is a list of functions in JSON format that you can invoke.
[
    {
        "name": "sensitive_data_detection",
        "description": "Find sensitive data in a commit",
        "parameters": {
            "hash": {
            "param_type": "hex",
            "description": "Hash number of commit containing sensitive information",
            "required": true
            }
            "file path": {
            "param_type": "string",
            "description": "The file containing sensitive information",
            "required": true
            }
            "issue line": {
            "param_type": "integer",
            "description": "Line where the found sensitive information starts",
            "required": true
            }
            "sensitive information type": {
            "param_type": "string",
            "description": "Type of sensitive information exposed",
            "required": true
            }
            "confidence": {
            "param_type": "float",
            "description": "Confidence of this part containing sensitive information",
            "required": true
            }
        }
    }
]<|eot_id|><|start_header_id|>user<|end_header_id|>
Is there any sensitive information exposed in this commit? {text} <|eot_id|><|start_header_id|>assistant<|end_header_id|>""")

    prompts = [prompt_template.format(text=item) for item in input_data]

    # Define additional parameters for prompting
    sampling_params = SamplingParams(
    temperature=0.0,
    max_tokens=20,
    top_p=1.0,
    stop=["\n"]
    )

    # TODO: If possible, stop the reports about Llama and CUDA from popping up in the shell
    result = llm.generate(input_data)
    print(result)
    return result


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
            decoded_path = diff_item.a_rawpath.decode(encoding='utf-8')
            targetfile = diff.tree / decoded_path
            # Since there have been issues with correct encoding, introducing the Universal Encoding Detector
            detector = UniversalDetector()
            with io.BytesIO(targetfile.data_stream.read()) as f:
                for line in f:
                    detector.feed(line)
                    if detector.done: break
                detector.close()
                file_encoding = detector.result['encoding']
                if file_encoding is not None:
                    files_in_commit[diff_item.a_rawpath] = f.read().decode(encoding=file_encoding)
        for diff_item in diffs_to_parent[diff].iter_change_type("M"):
            if diff_item.a_blob is not None:
                files_in_commit[diff_item.a_rawpath] = diff_item.a_blob.data_stream.read().decode('utf-8')
        changed_files.append(files_in_commit)

    commit_dict = {hexsha: {"message": message, "changed_files": files_in_commit} for hexsha, message, files_in_commit in zip(hashes, commit_messages, changed_files)}

    responses = llama_prompting(commit_dict.items())

    print(responses)

    # TODO: Additional layer of safety through entropy or regex

    # Save issues from dictionary to JSON file
    # Attributes for each issue: commit hash, file path, line/offset snippet, finding type, confidence
    json.dump(issue_dict, open(out, "w"), indent=4)


if __name__ == "__main__":
    # TODO: Make sure that the inputs provided by user cannot break the program (Error messages to catch cases and ask to try again?)
    # Parse all arguments entered in command line
    args = parser.parse_args(sys.argv[1:])
    threat_analysis(args.repo, args.n, args.out)
