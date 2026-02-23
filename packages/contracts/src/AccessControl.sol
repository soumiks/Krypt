// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./VaultRegistry.sol";

/// @title AccessControl
/// @notice Manages time-limited vendor access to vault chunks.
contract AccessControl {
    struct AccessGrant {
        address vendor;
        bytes32 chunkId;
        uint256 grantedAt;
        uint256 expiresAt;
        bool revoked;
    }

    VaultRegistry public immutable registry;

    /// vaultId => chunkId => vendor => AccessGrant
    mapping(bytes32 => mapping(bytes32 => mapping(address => AccessGrant))) public grants;
    /// vaultId => list of all grants (for audit log)
    mapping(bytes32 => AccessGrant[]) public accessLog;

    event AccessGranted(bytes32 indexed vaultId, bytes32 indexed chunkId, address indexed vendor, uint256 expiresAt);
    event AccessRevoked(bytes32 indexed vaultId, bytes32 indexed chunkId, address indexed vendor);

    error NotVaultOwner();
    error AccessNotFound();
    error InvalidExpiry();

    constructor(address _registry) {
        registry = VaultRegistry(_registry);
    }

    modifier onlyVaultOwner(bytes32 vaultId) {
        (address owner,,) = registry.getVault(vaultId);
        if (owner != msg.sender) revert NotVaultOwner();
        _;
    }

    /// @notice Grant time-limited access to a vendor for a specific chunk.
    function grantAccess(
        bytes32 vaultId,
        bytes32 chunkId,
        address vendor,
        uint256 expiresAt
    ) external onlyVaultOwner(vaultId) {
        if (expiresAt <= block.timestamp) revert InvalidExpiry();

        AccessGrant memory grant = AccessGrant({
            vendor: vendor,
            chunkId: chunkId,
            grantedAt: block.timestamp,
            expiresAt: expiresAt,
            revoked: false
        });

        grants[vaultId][chunkId][vendor] = grant;
        accessLog[vaultId].push(grant);

        emit AccessGranted(vaultId, chunkId, vendor, expiresAt);
    }

    /// @notice Revoke a vendor's access to a chunk.
    function revokeAccess(
        bytes32 vaultId,
        bytes32 chunkId,
        address vendor
    ) external onlyVaultOwner(vaultId) {
        AccessGrant storage grant = grants[vaultId][chunkId][vendor];
        if (grant.grantedAt == 0) revert AccessNotFound();

        grant.revoked = true;

        // Also record the revocation in the log
        accessLog[vaultId].push(AccessGrant({
            vendor: vendor,
            chunkId: chunkId,
            grantedAt: grant.grantedAt,
            expiresAt: grant.expiresAt,
            revoked: true
        }));

        emit AccessRevoked(vaultId, chunkId, vendor);
    }

    /// @notice Check if a vendor currently has access to a chunk.
    function hasAccess(
        bytes32 vaultId,
        bytes32 chunkId,
        address vendor
    ) external view returns (bool) {
        AccessGrant storage grant = grants[vaultId][chunkId][vendor];
        if (grant.grantedAt == 0) return false;
        if (grant.revoked) return false;
        if (block.timestamp >= grant.expiresAt) return false;
        return true;
    }

    /// @notice Get the full access log for a vault.
    function getAccessLog(bytes32 vaultId) external view returns (AccessGrant[] memory) {
        return accessLog[vaultId];
    }
}
