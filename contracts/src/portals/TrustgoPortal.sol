// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import { Ownable } from "openzeppelin-contracts/contracts/access/Ownable.sol";
import { AbstractPortal } from "../../interface/AbstractPortal.sol";

/**
 * @title Payable Portal
 * @author Trustalabs
 * @notice This contract is a Portal used by Trustalabs to issue attestations
 */
contract TrustgoPortal is AbstractPortal, Ownable {
  /// @dev Error thrown when the withdraw fails
  error WithdrawFail();

  constructor(address[] memory modules, address router) AbstractPortal(modules, router) Ownable() {}

  function withdraw(address payable to, uint256 amount) external override onlyOwner {
    (bool s, ) = to.call{ value: amount }("");
    if (!s) revert WithdrawFail();
  }
}
