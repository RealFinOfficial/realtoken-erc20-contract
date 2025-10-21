// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interface/IERC2612.sol";
import "./interface/IERC3009.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/Nonces.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

contract RealToken is ERC20Burnable, EIP712, Nonces, IERC2612, IERC3009
{
    constructor() ERC20("Real", "ASSET") EIP712("Real", "1") { 
        _mint(msg.sender, 1_000_000_000 * 10**18);
    }

    error RealTokenInvalidSignature();

    function decimals() public pure override returns (uint8) {
        return 18;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return super._domainSeparatorV4();
    }

    function _validateSignature(address signer, bytes32 encodeData, bytes memory signature) internal view {
        require(SignatureChecker.isValidSignatureNow(signer, MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR(), encodeData), signature), RealTokenInvalidSignature());
    }

    //ERC 2612 implementation
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    function _permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) internal {
        if (block.timestamp > deadline) {
            revert ERC2612ExpiredSignature(deadline);
        }
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));
        _validateSignature(owner, structHash, signature);

        _approve(owner, spender, value);
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external {
        _permit(owner, spender, value, deadline, signature);
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        _permit(owner, spender, value, deadline, abi.encodePacked(r, s, v));
    }

    //ERC 3009 implementation
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;
    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = 0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;
    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH = 0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }
    
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(v, r, s));
    }

    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _receiveWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(v, r, s));
    }

    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external  {
        _cancelAuthorization(authorizer, nonce, abi.encodePacked(v, r, s));
    }

    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) external {
       _transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }

    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) external {
        _receiveWithAuthorization(from, to, value, validAfter, validBefore, nonce, signature);
    }

    function cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) external  {
         _cancelAuthorization(authorizer, nonce, signature);
    }

    function _transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) internal {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _validateSignature(from, keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)), signature);
        _useAuthorization(from, nonce);

        _transfer(from, to, value);
    }

    function _receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature) internal {
        require(to == msg.sender, ERC3009CallerMustBeThePayee());
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _validateSignature(from, keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)), signature);
        _useAuthorization(from, nonce);

        _transfer(from, to, value);
    }

    function _cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) internal {
        require(!_authorizationStates[authorizer][nonce], ERC3009UsedOrCanceledAuthorization());
        _validateSignature(authorizer, keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)), signature);
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    function _requireValidAuthorization(address authorizer, bytes32 nonce, uint256 validAfter, uint256 validBefore) private view {
        require(block.timestamp > validAfter, ERC3009NotYetValidAuthorization(validAfter));
        require(block.timestamp < validBefore, ERC3009ExpiredAuthorization(validBefore));
        require(!_authorizationStates[authorizer][nonce], ERC3009UsedOrCanceledAuthorization());
    }

    function _useAuthorization(address authorizer, bytes32 nonce) private {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }

}
