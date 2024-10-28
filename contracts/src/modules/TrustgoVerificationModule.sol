// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import { AbstractModule } from "../../interface/AbstractModule.sol";
import { AttestationPayload } from "../../types/Structs.sol";
import { Ownable } from "openzeppelin-contracts/contracts/access/Ownable.sol";
import { ECDSA } from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title FeeChecker Module
 * @author Trustalabs
 * @notice This contract is an example of a module, able to charge a fee for attestations
 */
contract TrustgoVerificationModule is Ownable, AbstractModule {
  using ECDSA for bytes32;

  mapping(bytes32 schemaId => uint256 attestationFee) public attestationFees;
  mapping(address signer => uint256 passRate) public authorizedSigners;

  /// @notice Error thrown when an array length mismatch occurs
  error ArrayLengthMismatch();
  /// @notice Error thrown when an invalid attestation fee is provided
  error InvalidAttestationFee(uint256 value, uint256 fee, uint256 passRate);
  /// @notice Error thrown when a signer is not authorized by the module
  error SignerNotAuthorized(bytes32 messageHash, address messageSigner);
  /// @notice Error thrown when a signer is revoked
  error SignerRevoked(bytes32 messageHash, address messageSigner);
  /// @notice Error thrown when a schemaId is not accepted by the module
  error SchemaIdNotAccepted(bytes32 schemaId);
  /// @notice Error thrown when a schemaId is not accepted by the module
  error SchemaIdRevoked(bytes32 schemaId);

  /**
   * @notice Set the fee required to attest
   * @param _attestationFees The fees required to attest
   * @param schemaIds The schemaIds to set the fee for
   */
  function setFees(bytes32[] memory schemaIds, uint256[] memory _attestationFees) public onlyOwner {
    if (schemaIds.length != _attestationFees.length) revert ArrayLengthMismatch();

    for (uint256 i = 0; i < schemaIds.length; i++) {
      attestationFees[schemaIds[i]] = _attestationFees[i];
    }
  }

  /**
   * @notice Set the accepted status of schemaIds
   * @param signers The signers to be set
   * @param signerPassRate The authorization status of signers
   */
  function setAuthorizedSigners(address[] memory signers, uint256[] memory signerPassRate) public onlyOwner {
    if (signers.length != signerPassRate.length) revert ArrayLengthMismatch();

    for (uint256 i = 0; i < signers.length; i++) {
      authorizedSigners[signers[i]] = signerPassRate[i];
    }
  }

  function getHash(AttestationPayload memory _attestationPayload) public pure returns (bytes32) {
    bytes32 messageHash = keccak256(
      abi.encode(
        _attestationPayload.schemaId,
        _attestationPayload.expirationDate,
        _attestationPayload.subject,
        _attestationPayload.attestationData
      )
    );
    return messageHash;
  }

  /**
   * @notice The main method for the module, running the check
   * @param _value The value sent for the attestation
   */
  function run(
    AttestationPayload memory _attestationPayload,
    bytes memory _validationPayload,
    address /*_txSender*/,
    uint256 _value
  ) public view override {
    bytes32 messageHash = getHash(_attestationPayload);
    address messageSigner = messageHash.toEthSignedMessageHash().recover(_validationPayload);

    if (authorizedSigners[messageSigner] == 0) revert SignerNotAuthorized(messageHash, messageSigner);

    if (attestationFees[_attestationPayload.schemaId] == 0) revert SchemaIdNotAccepted(_attestationPayload.schemaId);

    uint256 attestationFee = (attestationFees[_attestationPayload.schemaId] * authorizedSigners[messageSigner]) / 100;
    if (_value < attestationFee)
      revert InvalidAttestationFee(
        _value,
        attestationFees[_attestationPayload.schemaId],
        authorizedSigners[messageSigner]
      );
  }
}
