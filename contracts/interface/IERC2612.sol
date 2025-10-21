// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC2612 {
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external;
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    error ERC2612ExpiredSignature(uint256 deadline);
    
}
