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

    # Define a minimal chat template
    chat_template = (
        "{% for message in messages %}"
        "{% if message['role'] == 'system' %}"
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n{{ message['content'] }}<|eot_id|>"
        "{% elif message['role'] == 'user' %}"
        "<|start_header_id|>user<|end_header_id|>\n{{ message['content'] }}<|eot_id|>"
        "{% elif message['role'] == 'assistant' %}"
        "<|start_header_id|>assistant<|end_header_id|>\n{{ message['content'] }}<|eot_id|>"
        "{% endif %}"
        "{% endfor %}"
        "<|start_header_id|>assistant<|end_header_id|>\n"
    )

    tokenizer.chat_template = chat_template
    print(tokenizer.chat_template)

    # Save the tokenizer (this updates tokenizer_config.json on disk)
    local_tokenizer_path = os.path.join(directory, "llama3_1_8b_tokenizer_with_chat_template")
    tokenizer.save_pretrained(local_tokenizer_path)

    # Create an LLM instance
    llm = LLM(dtype="float16",
              model=model_name,
              tokenizer=local_tokenizer_path,
              download_dir=directory,
              gpu_memory_utilization=0.7,
              tensor_parallel_size=4,
              max_num_seqs=100,
              max_model_len=15000
              )

    # Prompt template definition
    # Attributes for each issue: commit hash, file path, line/offset snippet, finding type, confidence

    # commit_dict = {hexsha: {"message": message, "changed_files": files_in_commit} for hexsha, message, files_in_commit in zip(hashes, commit_messages, changed_files)}
    results = []
    for hexsha in input_data:
        input_as_string = f"""{hexsha} {input_data[hexsha]["message"]}
            """
        for filename, file_content in input_data[hexsha]["changed_files"].items():
            input_as_string += f"{filename}\n{file_content}"

        conversation = [
            {"role": "system", "content": """You are a helpful expert in detecting sensitive information in Git repositories. You are given all changed files in a commit.
Each time you find any sensitive information in a file, extract values of ONLY the following: "hash number", "file path", "line with issue", "sensitive information type" and "confidence of you being right".
Insert the values in the brackets into each issue in the following Python dictionary format: {"hash": (str), "file_path": (str), "issue_line": int, "info_type": (str), "confidence": (float)}"""},
            {"role": "user", "content": """e1d1963cba51164273adc68cf23af275 Created e-mail connection function
e_mail_server.py
def connect_to_email():
    email = "user@example.com"
    password = "emailpassword"
    smtp_server = "smtp.example.com"
    smtp_port = 587
    return f'Email: {email}, Password: {password}, SMTP server: {smtp_server}, SMTP port: {smtp_port}'"""},
            {"role": "assistant", "content": """[{"hash": "e1d1963cba51164273adc68cf23af275", "file_path": "e_mail_server.py", "issue_line": 2, "info_type": "e-mail", "confidence":0.99},
{"hash": "e1d1963cba51164273adc68cf23af275", "file_path": "e_mail_server.py", "issue_line": 3, "info_type": "password", "confidence":0.8},
{"hash": "e1d1963cba51164273adc68cf23af275", "file_path": "e_mail_server.py", "issue_line": 4, "info_type": "url", "confidence":0.6},
{"hash": "e1d1963cba51164273adc68cf23af275", "file_path": "e_mail_server.py", "issue_line": 5, "info_type": "port", "confidence":0.9}]"""},
            {
                "role": "user",
                "content": input_as_string},
        ]

        # Define additional parameters for prompting
        # top_p=1.0
        sampling_params = SamplingParams(
            temperature=0.0,
            top_p=1.0,
            max_tokens=1000
        )
        # TODO: If possible, stop the reports about Llama and CUDA from popping up in the shell
        result = llm.chat(conversation, sampling_params=sampling_params, use_tqdm=True)
        for output in result:
            string_output = output.outputs[0].text.strip()
            print(f"String output: {string_output}")
        results.append(string_output)
    print(f"Results: {results}")
    return results


def threat_analysis(repo_link, n, out):
    # Create a dictionary to store issues found by Llama model (is a defaultdict needed?)
    issue_dict = {}

    # Extract all relevant commits, messages and diffs from repo
    if check_if_path(repo_link):
        repo = Repo(repo_link)
    else:
        cwd = Path.cwd()
        repo = Repo.clone_from(repo_link, cwd.parent / "New_Repo")

    # Extracting the necessary information about each commit in advance
    hashes = [commit.hexsha for commit in repo.iter_commits(all=True, max_count=n)]
    commit_messages = [commit.message for commit in repo.iter_commits(all=True, max_count=n)]

    # TODO: Make sure there are no "out of range" errors!
    n_commit_list = list(repo.iter_commits(all=True))[:n]
    comp_commits = list(repo.iter_commits(all=True))[1:n + 1]
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
                    files_in_commit[diff_item.a_rawpath.decode('utf-8')] = f.read().decode(encoding=file_encoding)
        for diff_item in diffs_to_parent[diff].iter_change_type("M"):
            if diff_item.a_blob is not None:
                files_in_commit[diff_item.a_rawpath.decode('utf-8')] = diff_item.a_blob.data_stream.read().decode(
                    'utf-8')
        changed_files.append(files_in_commit)

    commit_dict = {hexsha: {"message": message, "changed_files": files_in_commit} for hexsha, message, files_in_commit
                   in zip(hashes, commit_messages, changed_files)}
    responses = llama_prompting(commit_dict)

    print(f"Responses: {responses}")

    # TODO: Additional layer of safety through entropy or regex

    # Save issues from dictionary to JSON file
    # Attributes for each issue: commit hash, file path, line/offset snippet, finding type, confidence
    json.dump(issue_dict, open(out, "w"), indent=4)


if __name__ == "__main__":
    # TODO: Make sure that the inputs provided by user cannot break the program (Error messages to catch cases and ask to try again?)
    # Parse all arguments entered in command line
    args = parser.parse_args(sys.argv[1:])
    threat_analysis(args.repo, args.n, args.out)