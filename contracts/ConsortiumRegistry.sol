// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SENTINEL-FL consortium registry
/// @notice Participant registration and access control for the federated AML consortium,
///         plus write-once anchoring of each round's Merkle root (audit anchoring).
/// @dev    Holds identities and decisions only: no transaction data, no model weights.
contract ConsortiumRegistry {
    enum Status { None, Pending, Approved, Revoked, Quarantined }

    struct Bank {
        bytes32 pubKey;        // Ed25519 public key the bank signs its updates with
        string jurisdiction;   // e.g. "France"
        address wallet;        // account that sent the join request
        Status status;
        uint64 updatedAt;
    }

    struct RoundAnchor {
        bytes32 merkleRoot;    // Merkle root of the accepted update hashes
        bytes32 modelHash;     // hash of the resulting global model
        uint64 anchoredAt;
    }

    address public operator;   // consortium operator (aggregator)
    address public regulator;  // supervisor: may revoke or quarantine, cannot approve

    mapping(string => Bank) private banks;
    string[] public bankIds;
    mapping(bytes32 => mapping(uint256 => RoundAnchor)) public anchors; // runId => round => anchor

    event JoinRequested(string bankId, bytes32 pubKey, string jurisdiction, address wallet);
    event AccessChanged(string bankId, Status status, address by, string reason);
    event RoundAnchored(bytes32 runId, uint256 round, bytes32 merkleRoot, bytes32 modelHash);

    modifier onlyOperator() { require(msg.sender == operator, "only operator"); _; }
    modifier onlyGovernance() { require(msg.sender == operator || msg.sender == regulator, "only operator or regulator"); _; }

    constructor(address _regulator) {
        operator = msg.sender;
        regulator = _regulator;
    }

    function requestJoin(string calldata bankId, bytes32 pubKey, string calldata jurisdiction) external {
        require(banks[bankId].status == Status.None, "bank already registered");
        require(pubKey != bytes32(0), "empty key");
        banks[bankId] = Bank(pubKey, jurisdiction, msg.sender, Status.Pending, uint64(block.timestamp));
        bankIds.push(bankId);
        emit JoinRequested(bankId, pubKey, jurisdiction, msg.sender);
    }

    function approve(string calldata bankId) external onlyOperator {
        Status s = banks[bankId].status;
        require(s == Status.Pending || s == Status.Revoked, "not pending or revoked");
        _set(bankId, Status.Approved, "approved");
    }

    function revoke(string calldata bankId, string calldata reason) external onlyGovernance {
        require(banks[bankId].status != Status.None, "unknown bank");
        _set(bankId, Status.Revoked, reason);
    }

    function quarantine(string calldata bankId, string calldata reason) external onlyGovernance {
        require(banks[bankId].status == Status.Approved, "bank not active");
        _set(bankId, Status.Quarantined, reason);
    }

    function reinstate(string calldata bankId) external onlyOperator {
        require(banks[bankId].status == Status.Quarantined, "not quarantined");
        _set(bankId, Status.Approved, "reinstated");
    }

    function anchorRound(bytes32 runId, uint256 round, bytes32 merkleRoot, bytes32 modelHash) external onlyOperator {
        require(anchors[runId][round].anchoredAt == 0, "round already anchored");
        anchors[runId][round] = RoundAnchor(merkleRoot, modelHash, uint64(block.timestamp));
        emit RoundAnchored(runId, round, merkleRoot, modelHash);
    }

    /// @notice The access-control check the aggregator makes before it accepts an update.
    function isAuthorised(string calldata bankId, bytes32 pubKey) external view returns (bool) {
        Bank storage b = banks[bankId];
        return b.status == Status.Approved && b.pubKey == pubKey;
    }

    function getBank(string calldata bankId) external view returns (bytes32, string memory, address, Status, uint64) {
        Bank storage b = banks[bankId];
        return (b.pubKey, b.jurisdiction, b.wallet, b.status, b.updatedAt);
    }

    function bankCount() external view returns (uint256) { return bankIds.length; }

    function _set(string calldata bankId, Status s, string memory reason) private {
        banks[bankId].status = s;
        banks[bankId].updatedAt = uint64(block.timestamp);
        emit AccessChanged(bankId, s, msg.sender, reason);
    }
}
