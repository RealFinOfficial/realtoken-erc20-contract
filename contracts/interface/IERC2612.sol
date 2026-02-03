// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC-2612 standard as defined in the EIP.
 *
 * Adds the {permit} method, which can be used to change an account's ERC-20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */
interface IERC2612 {
    /**
     * @dev Sets `value` as the allowance of `spender` over `owner`'s tokens,
     * given `owner`'s signed approval.
     *
     * @param owner     The address of the token owner
     * @param spender   The address of the spender
     * @param value     The amount of tokens to approve
     * @param deadline  The time at which the signature expires (unix time)
     * @param signature The signature bytes
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external;

    /**
     * @dev Sets `value` as the allowance of `spender` over `owner`'s tokens,
     * given `owner`'s signed approval.
     *
     * @param owner    The address of the token owner
     * @param spender  The address of the spender
     * @param value    The amount of tokens to approve
     * @param deadline The time at which the signature expires (unix time)
     * @param v        v of the signature
     * @param r        r of the signature
     * @param s        s of the signature
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;

    /**
     * @dev The permit signature has expired.
     */
    error ERC2612ExpiredSignature(uint256 deadline);
}
