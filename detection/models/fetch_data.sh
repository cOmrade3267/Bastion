#!/usr/bin/env bash
# Bastion — dataset fetch helper (Phase 1, issue-driven)
# =====================================================
# The CICDDoS2019 / CIC-IDS2017 datasets are LICENSE-GATED and multi-GB, so the
# download is yours to run with YOUR credentials. This script does NOT bundle any
# data — it just creates the folder layout train_rf.py expects and (if you have
# the Kaggle CLI + token) pulls a mirror for you. For the authoritative source,
# use the UNB CIC links below and unzip the CSVs into the folders this prints.
#
#   Train/test protocol the model uses (see docs/EXECUTION_PLAN.md):
#     data/CICDDoS2019/CSV-01-12/*.csv   train day  (syn_flood, udp_flood, benign)
#     data/CICDDoS2019/CSV-03-11/*.csv   test  day
#     data/CICIDS2017/*.csv              slowloris source (not in CICDDoS2019)
#
# Usage:
#   ./fetch_data.sh                 # print layout + guidance; download if Kaggle set up
#   ./fetch_data.sh <owner>/<slug>  # download a specific Kaggle dataset slug
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$HERE/data"
mkdir -p "$DATA/CICDDoS2019" "$DATA/CICIDS2017"

echo "Dataset folders ready under: $DATA"
echo "  CICDDoS2019/CSV-01-12/*.csv   (train day)"
echo "  CICDDoS2019/CSV-03-11/*.csv   (test day)"
echo "  CICIDS2017/*.csv              (slowloris: CIC-IDS2017 Wednesday DoS CSVs)"
echo

echo "Authoritative sources (accept the licence, download the CSVs, not the pcaps):"
echo "  CICDDoS2019: https://www.unb.ca/cic/datasets/ddos-2019.html"
echo "  CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html"
echo

if ! command -v kaggle >/dev/null 2>&1; then
  echo "Kaggle CLI not found — do the manual download above, OR:"
  echo "    pip install kaggle"
  echo "    # place your API token at ~/.kaggle/kaggle.json (chmod 600)"
  echo "    kaggle datasets list -s cicddos2019     # pick a mirror slug"
  echo "    $0 <owner>/<slug>                        # then re-run with it"
  exit 0
fi

SLUG="${1:-}"
if [ -z "$SLUG" ]; then
  echo "Kaggle CLI present. Find a mirror and re-run with its slug:"
  echo "    kaggle datasets list -s cicddos2019"
  echo "    $0 <owner>/<slug>"
  exit 0
fi

echo "Downloading $SLUG -> $DATA/CICDDoS2019 (unzipping)..."
kaggle datasets download -d "$SLUG" -p "$DATA/CICDDoS2019" --unzip

echo
echo "Downloaded. Now verify the columns/labels map cleanly:"
echo "    cd \"$HERE\""
echo "    python -c \"from datasets import load_cicddos2019 as L; import glob; \\"
echo "       p=sorted(glob.glob('data/CICDDoS2019/**/*.csv', recursive=True)); \\"
echo "       d=L(p); print(d.shape); print(d['label'].value_counts())\""
echo
echo "Then train on the official split:"
echo "    python train_rf.py --data cicddos \\"
echo "       --train-csv 'data/CICDDoS2019/CSV-01-12/*.csv data/CICIDS2017/*.csv' \\"
echo "       --test-csv  'data/CICDDoS2019/CSV-03-11/*.csv' --cv"
