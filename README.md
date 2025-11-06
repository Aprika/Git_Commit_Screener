# Git_Commit_Screener
A Llama-powered cybersecurity tool to screen Git commits for possible vulnerabilities through diffs and commit messages.

# Install required files
Install dependencies in requirements.txt:
```
ip install -r requirements.txt
```

# Clone this repository
```
git clone https://github.com/Aprika/Git_Commit_Screener
```

# Bash input in command line
```
python ./git_scanning.py --repo <path|url> --n <commits> --out report.json

# Example
python ./git_scanning.py --repo 'https://github.com/Aprika/Git_Commit_Screener' --n 2 --out report.json  # Clones this repository in the parent folder of the working directory under name "New_Repo"
```

# Optional feature for using GPU of Linux-powered remote servers
bash model_run.slurm
