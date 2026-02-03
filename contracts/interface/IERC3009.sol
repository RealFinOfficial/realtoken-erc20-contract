// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC-3009 standard as defined in the EIP.
 *
 * Provides transfer and approval functionality via signed authorizations,
 * allowing token holders to delegate transfers without submitting transactions themselves.
 * Unlike ERC-2612, authorizations use time-based validity windows and random nonces.
 */
interface IERC3009 {
    /**
     * @dev Emitted when an authorization is used.
     * @param authorizer The address of the authorizer
     * @param nonce      The nonce of the used authorization
     */
    event AuthorizationUsed(
        address indexed authorizer,
        bytes32 indexed nonce
    );

    /**
     * @notice Returns the state of an authorization
     * @dev Nonces are randomly generated 32-byte data unique to the authorizer's
     * address
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @return True if the nonce is used
     */
    function authorizationState(
        address authorizer,
        bytes32 nonce
    ) external view returns (bool);

    /**
     * @notice Execute a transfer with a signed authorization
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @notice Execute a transfer with a signed authorization
     * @dev See {transferWithAuthorization-address-address-uint256-uint256-uint256-bytes32-uint8-bytes32-bytes32}.
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param signature     The signature bytes
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /**
     * @notice Receive a transfer with a signed authorization from the payer
     * @dev This has an additional check to ensure that the payee's address matches
     * the caller of this function to prevent front-running attacks. (See security
     * considerations)
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @notice Receive a transfer with a signed authorization from the payer
     * @dev See {receiveWithAuthorization-address-address-uint256-uint256-uint256-bytes32-uint8-bytes32-bytes32}.
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param signature     The signature bytes
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /**
     * @dev Emitted when an authorization is canceled.
     * @param authorizer The address of the authorizer
     * @param nonce      The nonce of the canceled authorization
     */
    event AuthorizationCanceled(
        address indexed authorizer,
        bytes32 indexed nonce
    );

    /**
     * @notice Attempt to cancel an authorization
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @notice Attempt to cancel an authorization
     * @dev See {cancelAuthorization-address-bytes32-uint8-bytes32-bytes32}.
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param signature     The signature bytes
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /**
     * @dev The authorization has expired.
     */
    error ERC3009ExpiredAuthorization(uint256 validBefore);

    /**
     * @dev The authorization is not yet valid.
     */
    error ERC3009NotYetValidAuthorization(uint256 validAfter);

    /**
     * @dev The authorization has already been used or canceled.
     */
    error ERC3009UsedOrCanceledAuthorization();

    /**
     * @dev The caller is not the payee specified in the authorization.
     */
    error ERC3009CallerMustBeThePayee();
}
