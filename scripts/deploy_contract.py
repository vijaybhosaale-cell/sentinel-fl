"""Compile and deploy contracts/ConsortiumRegistry.sol to a local dev chain (Anvil, Hardhat or Ganache).

    docker compose --profile chain up -d anvil          # or: anvil  /  npx hardhat node  /  npx ganache
    pip install -r requirements-chain.txt
    python scripts/deploy_contract.py --rpc http://127.0.0.1:8545
    SENTINEL_CHAIN=eth python -m sentinel aggregator --fresh       (PowerShell: $env:SENTINEL_CHAIN="eth")

Writes contracts/build/ConsortiumRegistry.json (ABI, address, roles). Account 0 = operator,
account 1 = regulator, accounts 2-4 = wallets of banks A, B, C (the chain's unlocked dev accounts).
"""
import argparse
import json
from pathlib import Path

import solcx
from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--rpc", default="http://127.0.0.1:8545")
ap.add_argument("--solc", default="0.8.24")
a = ap.parse_args()

solcx.install_solc(a.solc)
src = (ROOT / "contracts" / "ConsortiumRegistry.sol").read_text()
out = solcx.compile_source(src, output_values=["abi", "bin"], solc_version=a.solc)
_, c = next((k, v) for k, v in out.items() if k.endswith(":ConsortiumRegistry"))

w3 = Web3(Web3.HTTPProvider(a.rpc))
assert w3.is_connected(), f"no chain at {a.rpc}: start anvil first"
acc = w3.eth.accounts
tx = w3.eth.contract(abi=c["abi"], bytecode=c["bin"]).constructor(acc[1]).transact({"from": acc[0]})
rcpt = w3.eth.wait_for_transaction_receipt(tx)
info = {"address": rcpt.contractAddress, "abi": c["abi"], "rpc": a.rpc, "operator": acc[0], "regulator": acc[1],
        "bank_wallets": {"A": acc[2], "B": acc[3], "C": acc[4], "D": acc[5], "E": acc[6]},
        "deploy_tx": rcpt.transactionHash.hex(), "deploy_block": rcpt.blockNumber, "gas_used": rcpt.gasUsed}
(ROOT / "contracts" / "build").mkdir(exist_ok=True)
(ROOT / "contracts" / "build" / "ConsortiumRegistry.json").write_text(json.dumps(info, indent=1))
print(f"ConsortiumRegistry deployed at {rcpt.contractAddress} (block {rcpt.blockNumber}, gas {rcpt.gasUsed})")
print("operator", acc[0], "regulator", acc[1])
