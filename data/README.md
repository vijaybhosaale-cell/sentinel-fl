# Data

By default SENTINEL-FL generates synthetic AMLworld-like transactions, so nothing needs downloading.

To use the real IBM AMLworld data (Altman et al., NeurIPS 2023):
1. Download `HI-Small_Trans.csv` from Kaggle: https://www.kaggle.com/datasets/ealtman2019/ibm-transactions-for-anti-money-laundering-aml
2. Put it in this folder: `data/HI-Small_Trans.csv`
3. Run: `python -m sentinel run --config configs/amlworld.yaml`

Raw data files are git-ignored and must never be committed.
