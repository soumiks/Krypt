// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/VaultRegistry.sol";
import "../src/AccessControl.sol";

contract VaultRegistryTest is Test {
    VaultRegistry public registry;
    AccessControl public accessControl;
    address public alice = makeAddr("alice");
    address public vendor = makeAddr("vendor");
    bytes32 public vaultId = keccak256("alice-vault-1");
    bytes32 public chunkId = keccak256("medical-record-001");

    function setUp() public {
        registry = new VaultRegistry();
        accessControl = new AccessControl(address(registry));
    }

    function test_CreateVault() public {
        vm.prank(alice);
        registry.createVault(vaultId);

        (address owner, , uint256 chunkCount) = registry.getVault(vaultId);
        assertEq(owner, alice);
        assertEq(chunkCount, 0);
    }

    function test_RevertCreateDuplicateVault() public {
        vm.prank(alice);
        registry.createVault(vaultId);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(VaultRegistry.VaultAlreadyExists.selector, vaultId));
        registry.createVault(vaultId);
    }

    function test_RegisterChunk() public {
        vm.startPrank(alice);
        registry.createVault(vaultId);
        registry.registerChunk(vaultId, chunkId, "ipfs://QmABC123");
        vm.stopPrank();

        (string memory pointer, ) = registry.getChunk(vaultId, chunkId);
        assertEq(pointer, "ipfs://QmABC123");

        (, , uint256 chunkCount) = registry.getVault(vaultId);
        assertEq(chunkCount, 1);
    }

    function test_RevertNonOwnerRegisterChunk() public {
        vm.prank(alice);
        registry.createVault(vaultId);

        vm.prank(vendor);
        vm.expectRevert(abi.encodeWithSelector(VaultRegistry.NotVaultOwner.selector, vaultId, vendor));
        registry.registerChunk(vaultId, chunkId, "ipfs://QmABC123");
    }

    function test_GrantAndCheckAccess() public {
        vm.prank(alice);
        registry.createVault(vaultId);

        vm.prank(alice);
        registry.registerChunk(vaultId, chunkId, "ipfs://QmABC123");

        uint256 expiry = block.timestamp + 1 days;

        vm.prank(alice);
        accessControl.grantAccess(vaultId, chunkId, vendor, expiry);

        assertTrue(accessControl.hasAccess(vaultId, chunkId, vendor));
    }

    function test_AccessExpiresAfterTime() public {
        vm.prank(alice);
        registry.createVault(vaultId);

        uint256 expiry = block.timestamp + 1 hours;

        vm.prank(alice);
        accessControl.grantAccess(vaultId, chunkId, vendor, expiry);

        assertTrue(accessControl.hasAccess(vaultId, chunkId, vendor));

        vm.warp(expiry + 1);
        assertFalse(accessControl.hasAccess(vaultId, chunkId, vendor));
    }

    function test_RevokeAccess() public {
        vm.prank(alice);
        registry.createVault(vaultId);

        uint256 expiry = block.timestamp + 1 days;

        vm.prank(alice);
        accessControl.grantAccess(vaultId, chunkId, vendor, expiry);
        assertTrue(accessControl.hasAccess(vaultId, chunkId, vendor));

        vm.prank(alice);
        accessControl.revokeAccess(vaultId, chunkId, vendor);
        assertFalse(accessControl.hasAccess(vaultId, chunkId, vendor));
    }
}
