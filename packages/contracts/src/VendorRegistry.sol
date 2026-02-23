// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title VendorRegistry
/// @notice Registry of approved vendors who can request data access.
contract VendorRegistry {
    struct Vendor {
        string name;
        string vendorType; // e.g., "hospital", "insurer", "lab"
        address wallet;
        uint256 registeredAt;
        bool active;
        bool exists;
    }

    mapping(address => Vendor) public vendors;
    address[] public vendorList;
    address public admin;

    event VendorRegistered(address indexed vendor, string name, string vendorType);
    event VendorDeactivated(address indexed vendor);
    event VendorActivated(address indexed vendor);

    error OnlyAdmin();
    error VendorAlreadyExists();
    error VendorNotFound();

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    /// @notice Register a new vendor.
    function registerVendor(
        address wallet,
        string calldata name,
        string calldata vendorType
    ) external onlyAdmin {
        if (vendors[wallet].exists) revert VendorAlreadyExists();

        vendors[wallet] = Vendor({
            name: name,
            vendorType: vendorType,
            wallet: wallet,
            registeredAt: block.timestamp,
            active: true,
            exists: true
        });
        vendorList.push(wallet);

        emit VendorRegistered(wallet, name, vendorType);
    }

    /// @notice Deactivate a vendor.
    function deactivateVendor(address wallet) external onlyAdmin {
        if (!vendors[wallet].exists) revert VendorNotFound();
        vendors[wallet].active = false;
        emit VendorDeactivated(wallet);
    }

    /// @notice Reactivate a vendor.
    function activateVendor(address wallet) external onlyAdmin {
        if (!vendors[wallet].exists) revert VendorNotFound();
        vendors[wallet].active = true;
        emit VendorActivated(wallet);
    }

    /// @notice Check if a vendor is registered and active.
    function isActiveVendor(address wallet) external view returns (bool) {
        return vendors[wallet].exists && vendors[wallet].active;
    }

    /// @notice Get the count of registered vendors.
    function vendorCount() external view returns (uint256) {
        return vendorList.length;
    }
}
