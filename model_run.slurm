#!/bin/bash
#SBATCH --job-name=llama_commit_extraction
#SBATCH --ntasks=1
#SBATCH --partition=eightgpu
#SBATCH --qos=eightgpu
#SBATCH --cpus-per-task=4
#SBATCH --time=00:30:00

# === LOGGING SETUP ===
mkdir -p $PWD/logs
ORIGDIR=${PWD}
TIMESTAMP=${date +"%Y-%m-%d_%H-M-%S"}
LOGFILE=$ORIGDIR/logs/llama_run_{TIMESTAMP}.logs

# === TMPDIR SETUP ===
export TMPDIR=$ORIGDIR/tmp_${USER}_$SLURM_JOB_ID
mkdir -p "$TMPDIR"
trap "rm -rf $TMPDIR" EXIT

echo "[$(date)] Copying files to a temporary directory..." | tee -a "$LOGFILE"
cp $ORIGDIR/git_scanning.py "$TMPDIR"

cd "$TMPDIR"

# === GPU SETUP ===
echo "[$(date)] Configuring GPU settings....." | tee -a "$LOGFILE"
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

# == RUN PROGRAM ==
echo "[$(date)] Running Git Screening Tool......." | tee -a "$LOGFILE"
python ./git_scanning.py --repo "https://github.com/Aprika/Computational_Linguistics_programs" --n 3 --out report.json 2>&1 | tee -a "$LOGFILE"

# == OUTPUT BACKUP ==
echo "[$(date)] Copying results back to desktop......" | tee -a "$LOGFILE"
mkdir -p $ORIGDIR/results
cp *.json $ORIGDIR/results/

echo "[$(date)] Job finished." | tee -a "$LOGFILE"


