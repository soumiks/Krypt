// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title VaultRegistry
/// @notice Registers vaults and their data chunks on-chain.
/// @dev Each vault is owned by its creator. Chunks store pointers to off-chain encrypted data.
contract VaultRegistry {
    struct Vault {
        address owner;
        uint256 createdAt;
        uint256 chunkCount;
        bool exists;
    }

    struct Chunk {
        bytes32 chunkId;
        string storagePointer;
        uint256 createdAt;
        bool exists;
    }

    /// vaultId => Vault
    mapping(bytes32 => Vault) public vaults;
    /// vaultId => chunkId => Chunk
    mapping(bytes32 => mapping(bytes32 => Chunk)) public chunks;
    /// vaultId => list of chunk IDs
    mapping(bytes32 => bytes32[]) public vaultChunkIds;

    event VaultCreated(bytes32 indexed vaultId, address indexed owner);
    event ChunkRegistered(bytes32 indexed vaultId, bytes32 indexed chunkId, string storagePointer);

    error VaultAlreadyExists(bytes32 vaultId);
    error VaultNotFound(bytes32 vaultId);
    error ChunkAlreadyExists(bytes32 vaultId, bytes32 chunkId);
    error NotVaultOwner(bytes32 vaultId, address caller);

    modifier onlyVaultOwner(bytes32 vaultId) {
        if (!vaults[vaultId].exists) revert VaultNotFound(vaultId);
        if (vaults[vaultId].owner != msg.sender) revert NotVaultOwner(vaultId, msg.sender);
        _;
    }

    /// @notice Create a new vault.
    /// @param vaultId Unique identifier for the vault (derived from user's public key hash).
    function createVault(bytes32 vaultId) external {
        if (vaults[vaultId].exists) revert VaultAlreadyExists(vaultId);

        vaults[vaultId] = Vault({
            owner: msg.sender,
            createdAt: block.timestamp,
            chunkCount: 0,
            exists: true
        });

        emit VaultCreated(vaultId, msg.sender);
    }

    /// @notice Register a data chunk in a vault.
    /// @param vaultId The vault to add the chunk to.
    /// @param chunkId Unique identifier for the chunk.
    /// @param storagePointer URI or CID pointing to the encrypted chunk data.
    function registerChunk(
        bytes32 vaultId,
        bytes32 chunkId,
        string calldata storagePointer
    ) external onlyVaultOwner(vaultId) {
        if (chunks[vaultId][chunkId].exists) revert ChunkAlreadyExists(vaultId, chunkId);

        chunks[vaultId][chunkId] = Chunk({
            chunkId: chunkId,
            storagePointer: storagePointer,
            createdAt: block.timestamp,
            exists: true
        });
        vaultChunkIds[vaultId].push(chunkId);
        vaults[vaultId].chunkCount++;

        emit ChunkRegistered(vaultId, chunkId, storagePointer);
    }

    /// @notice Get vault metadata.
    function getVault(bytes32 vaultId)
        external
        view
        returns (address owner, uint256 createdAt, uint256 chunkCount)
    {
        if (!vaults[vaultId].exists) revert VaultNotFound(vaultId);
        Vault storage v = vaults[vaultId];
        return (v.owner, v.createdAt, v.chunkCount);
    }

    /// @notice Get chunk metadata.
    function getChunk(bytes32 vaultId, bytes32 chunkId)
        external
        view
        returns (string memory storagePointer, uint256 createdAt)
    {
        if (!chunks[vaultId][chunkId].exists) revert VaultNotFound(vaultId);
        Chunk storage c = chunks[vaultId][chunkId];
        return (c.storagePointer, c.createdAt);
    }
}
