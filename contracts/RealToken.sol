// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interface/IERC2612.sol";
import "./interface/IERC3009.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/Nonces.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

/**
 * @dev ERC-20 token with ERC-2612 permit and ERC-3009 transfer authorization support.
 *
 * Extends OpenZeppelin's {ERC20Burnable}, {EIP712}, and {Nonces} contracts,
 * and implements {IERC2612} and {IERC3009} interfaces. Supports both EOA (ECDSA)
 * and smart contract (ERC-1271) signature verification via {SignatureChecker}.
 */
contract RealToken is ERC20Burnable, EIP712, Nonces, IERC2612, IERC3009
{
    /**
     * @dev Sets the token name to "REAL", symbol to "ASSET", and EIP-712 domain name to "REAL" with version "1".
     * Mints 1,000,000,000 tokens (with 18 decimals) to the deployer.
     */
    constructor() ERC20("REAL", "ASSET") EIP712("REAL", "1") {
        _mint(msg.sender, 1_000_000_000 * 10**18);
    }

    /**
     * @dev The signature provided is not valid for the given signer and data.
     */
    error RealTokenInvalidSignature();

    /**
     * @dev Returns the number of decimals used to get the token's user representation.
     * @return The number of decimals (18).
     */
    function decimals() public pure override returns (uint8) {
        return 18;
    }

    /**
     * @dev Returns the EIP-712 domain separator for the current chain.
     * @return The domain separator as a bytes32 hash.
     */
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return super._domainSeparatorV4();
    }

    /**
     * @dev Validates a signature against the EIP-712 typed data hash.
     *
     * Uses {SignatureChecker} to support both EOA (ECDSA) and smart contract (ERC-1271) signatures.
     *
     * Requirements:
     *
     * - The signature must be valid for the given `signer` and `encodeData`.
     *
     * @param signer     The expected signer address
     * @param encodeData The EIP-712 struct hash to verify against
     * @param signature  The signature bytes
     */
    function _validateSignature(address signer, bytes32 encodeData, bytes memory signature) internal view {
        require(SignatureChecker.isValidSignatureNow(signer, MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR(), encodeData), signature), RealTokenInvalidSignature());
    }

    // ============ ERC-2612 Implementation ============

    /// @dev keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    /**
     * @dev Internal implementation of the ERC-2612 permit.
     *
     * Validates the deadline, constructs the EIP-712 struct hash, verifies the signature,
     * and sets the allowance.
     *
     * Emits an {IERC20-Approval} event.
     *
     * Requirements:
     *
     * - `block.timestamp` must be less than or equal to `deadline`.
     * - The signature must be valid for the `owner`.
     *
     * @param owner     The token owner granting the allowance
     * @param spender   The address being approved to spend tokens
     * @param value     The amount of tokens approved
     * @param deadline  The time at which the signature expires (unix time)
     * @param signature The signature bytes
     */
    function _permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) internal {
        if (block.timestamp > deadline) {
            revert ERC2612ExpiredSignature(deadline);
        }
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));
        _validateSignature(owner, structHash, signature);

        _approve(owner, spender, value);
    }

    /**
     * @dev See {IERC2612-permit}.
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external {
        _permit(owner, spender, value, deadline, signature);
    }

    /**
     * @dev See {IERC2612-permit}.
     *
     * Accepts the `v`, `r`, and `s` signature components and packs them into bytes.
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        _permit(owner, spender, value, deadline, abi.encodePacked(r, s, v));
    }

    // ============ ERC-3009 Implementation ============

    /// @dev keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;
    /// @dev keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = 0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;
    /// @dev keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH = 0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

    /// @dev Mapping of authorizer address => nonce => authorization state (true if used or canceled).
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    /**
     * @dev See {IERC3009-authorizationState}.
     */
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    /**
     * @dev See {IERC3009-transferWithAuthorization}.
     *
     * Accepts the `v`, `r`, and `s` signature components and packs them into bytes.
     */
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /**
     * @dev See {IERC3009-receiveWithAuthorization}.
     *
     * Accepts the `v`, `r`, and `s` signature components and packs them into bytes.
     */
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _receiveWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /**
     * @dev See {IERC3009-cancelAuthorization}.
     *
     * Accepts the `v`, `r`, and `s` signature components and packs them into bytes.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external  {
        _cancelAuthorization(authorizer, nonce, abi.encodePacked(r, s, v));
    }

    /**
     * @dev See {IERC3009-transferWithAuthorization}.
     */
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) external {
       _transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }

    /**
     * @dev See {IERC3009-receiveWithAuthorization}.
     */
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) external {
        _receiveWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }

    /**
     * @dev See {IERC3009-cancelAuthorization}.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) external  {
         _cancelAuthorization(authorizer, nonce, signature);
    }

    /**
     * @dev Executes a transfer using a signed authorization.
     *
     * Validates the authorization timing and nonce, verifies the EIP-712 signature,
     * marks the authorization as used, and transfers tokens.
     *
     * Emits a {Transfer} event via {ERC20-_transfer}.
     * Emits an {AuthorizationUsed} event.
     *
     * @param from        Payer's address (Authorizer)
     * @param to          Payee's address
     * @param value       Amount to be transferred
     * @param validAfter  The time after which this is valid (unix time)
     * @param validBefore The time before which this is valid (unix time)
     * @param nonce       Unique nonce
     * @param signature   The signature bytes
     */
    function _transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) internal {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _validateSignature(from, keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)), signature);
        _useAuthorization(from, nonce);

        _transfer(from, to, value);
    }

    /**
     * @dev Executes a transfer using a signed authorization, with the additional requirement
     * that the caller must be the payee. This prevents front-running attacks where a third
     * party could observe the authorization and submit the transaction first.
     *
     * Emits a {Transfer} event via {ERC20-_transfer}.
     * Emits an {AuthorizationUsed} event.
     *
     * Requirements:
     *
     * - `to` must be equal to `msg.sender`.
     *
     * @param from        Payer's address (Authorizer)
     * @param to          Payee's address (must be msg.sender)
     * @param value       Amount to be transferred
     * @param validAfter  The time after which this is valid (unix time)
     * @param validBefore The time before which this is valid (unix time)
     * @param nonce       Unique nonce
     * @param signature   The signature bytes
     */
    function _receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) internal {
        require(to == msg.sender, ERC3009CallerMustBeThePayee());
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _validateSignature(from, keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)), signature);
        _useAuthorization(from, nonce);

        _transfer(from, to, value);
    }

    /**
     * @dev Cancels an authorization, preventing it from being used in the future.
     *
     * Emits an {AuthorizationCanceled} event.
     *
     * Requirements:
     *
     * - The authorization must not have been already used or canceled.
     *
     * @param authorizer Authorizer's address
     * @param nonce      Nonce of the authorization to cancel
     * @param signature  The signature bytes
     */
    function _cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) internal {
        require(!_authorizationStates[authorizer][nonce], ERC3009UsedOrCanceledAuthorization());
        _validateSignature(authorizer, keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)), signature);
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /**
     * @dev Validates the timing and nonce of an authorization.
     *
     * Requirements:
     *
     * - `block.timestamp` must be greater than `validAfter`.
     * - `block.timestamp` must be less than `validBefore`.
     * - The nonce must not have been previously used or canceled.
     *
     * @param authorizer Authorizer's address
     * @param nonce      Nonce of the authorization
     * @param validAfter The time after which this is valid (unix time)
     * @param validBefore The time before which this is valid (unix time)
     */
    function _requireValidAuthorization(address authorizer, bytes32 nonce, uint256 validAfter, uint256 validBefore) private view {
        require(block.timestamp > validAfter, ERC3009NotYetValidAuthorization(validAfter));
        require(block.timestamp < validBefore, ERC3009ExpiredAuthorization(validBefore));
        require(!_authorizationStates[authorizer][nonce], ERC3009UsedOrCanceledAuthorization());
    }

    /**
     * @dev Marks an authorization nonce as used.
     *
     * Emits an {AuthorizationUsed} event.
     *
     * @param authorizer Authorizer's address
     * @param nonce      Nonce to mark as used
     */
    function _useAuthorization(address authorizer, bytes32 nonce) private {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }

}
