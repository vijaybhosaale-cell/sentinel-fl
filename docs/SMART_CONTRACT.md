# Smart-contract registry (`contracts/ConsortiumRegistry.sol`)

The brief asks for smart contracts for participant registration and access control. `ConsortiumRegistry` is
the consortium's access contract: the aggregator accepts an update **only if the contract says the bank and its key
are authorised**, and it anchors every round's Merkle root on-chain (write-once).

| Function | Who may call | Rule |
| --- | --- | --- |
| `requestJoin(bankId, pubKey, jurisdiction)` | any bank wallet | only once per bank ID (blocks impersonation); status → Pending |
| `approve(bankId)` | operator | Pending or Revoked → Approved |
| `revoke(bankId, reason)` | operator **or regulator** | any → Revoked |
| `quarantine(bankId, reason)` | operator **or regulator** | Approved → Quarantined |
| `reinstate(bankId)` | operator | Quarantined → Approved |
| `anchorRound(runId, round, merkleRoot, modelHash)` | operator | write-once per (run, round) |
| `isAuthorised(bankId, pubKey)` | anyone (view) | Approved **and** key matches |

Separation of duties: the regulator can stop a bank but cannot admit one; a bank cannot approve itself.
The contract stores identities and decisions only: no transaction data and no model weights (GDPR data minimisation).

## Two backends, same rules

| Backend | When | How |
| --- | --- | --- |
| Simulated (default) | demo, tests, no blockchain node | `sentinel/registry_chain.py: SimRegistry` re-implements every `require` with the same messages and keeps an append-only, hash-linked block log in `chain.json` |
| Ethereum | full on-chain demo | `SENTINEL_CHAIN=eth`, contract deployed on a local Anvil / Hardhat / Ganache chain |

Both appear on the **Registry & access** page: contract state per bank, and the contract transactions with block numbers.

## On-chain run (local Ethereum)

```powershell
docker compose --profile chain up -d anvil            # or install Foundry and run: anvil
pip install -r requirements-chain.txt
python scripts/deploy_contract.py --rpc http://127.0.0.1:8545
$env:SENTINEL_CHAIN="eth"
python -m sentinel cluster --fresh
```

The deploy script compiles the contract with solc 0.8.24 (downloaded by py-solc-x), deploys it from dev account 0
(operator; account 1 is the regulator, accounts 2–4 the wallets of Banks A–C) and writes
`contracts/build/ConsortiumRegistry.json`. Use only a local development chain: the dev accounts are public.

## Tests

`tests/test_chain.py` checks the lifecycle, separation of duties, impersonation, write-once anchoring and that an
edited block is detected. `tests/test_nodes.py` checks that a quarantine decided by the aggregator is recorded in the
contract and that every round is anchored. The Solidity source itself is compiled on the deploy machine (no compiler
in the build environment), so run the deploy script once before the demo.

Production note: Hyperledger Fabric (named in the brief as optional) would replace the local chain with a permissioned
network run by the banks and the supervisor; the contract's rules map directly onto Fabric chaincode.
