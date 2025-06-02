// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Base64} from "solady/utils/Base64.sol";
import {RSA} from "openzeppelin-contracts/contracts/utils/cryptography/RSA.sol";

/// @title AzureTDXErrors
/// @notice Error definitions for Azure TDX attestation validation
library AzureTDXErrors {
    error InvalidMagicValue(uint32 actual, uint32 expected);
    error InvalidAttestationType(uint16 actual, uint16 expected);
    error InvalidExtraDataLength(uint16 actual, uint16 expected);
    error InvalidPCRDigestLength(uint256 actual, uint256 expected);
    error InvalidPCRSelectionCount(uint32 actual, uint32 expected);
    error InvalidPCRBitmap(uint32 actual, uint32 expected);
    error PCRDigestMismatch(bytes32 actual, bytes32 expected);
    error RuntimeDataHashMismatch(bytes32 actual, bytes32 expected);
    error ExtraDataMismatch(bytes32 actual, bytes32 expected);
    error AttestationReportHashMismatch(bytes32 actual, bytes32 expected);
    error DuplicatePCR(uint256 index);
    error InvalidPCRIndex(uint256 index);
    error PCRMismatch(uint256 entryIndex);
    error QuoteTooShort(uint256 actual, uint256 required);
    error InvalidHashAlgorithm(uint16 actual, uint16 expected);
    error InvalidSignature();
}

/// @title AzureTDXConstants
/// @notice Constants for Azure TDX attestation validation
library AzureTDXConstants {
    // TPM Quote Constants
    uint32 internal constant TPMS_GENERATED_VALUE = 0xff544347;
    uint16 internal constant TAG_ATTEST_QUOTE = 0x8018;

    // Structure sizes
    // Literals so they can be used in assembly
    uint256 internal constant QUOTE_HEADER_SIZE = 6; // magic(4) + type(2)
    uint256 internal constant CLOCK_INFO_SIZE = 17; // clock(8) + resetCount(4) + restartCount(4) + safe(1)
    uint256 internal constant FIRMWARE_VERSION_SIZE = 8;
    uint256 internal constant SHA256_DIGEST_SIZE = 32;
    uint16 internal constant TPM_NONCE_SIZE = 32;

    // PCR Constants
    uint32 internal constant EXPECTED_PCR_BITMAP = 0xffffff; // All 24 PCRs
    uint32 internal constant PCR_COUNT = 24;

    // TDX Quote Constants
    uint256 internal constant TDX_REPORT_DATA_OFFSET = 0x238;
    uint256 internal constant TDX_REPORT_DATA_SIZE = 64;

    // RSA Constants
    uint32 internal constant DEFAULT_RSA_EXPONENT = 65537;
}

/// @title AzureTDX
/// @notice Library for validating Azure TDX attestations with TPM quotes
/// This library is compatible with the Constellation validation standard,
/// relies on some initial pre-processing to remove unnecessary data and
/// takes many assumptions over the data instead of doing a full sanity check.
library AzureTDX {
    /// @notice Minimal TPM quote structure containing only required fields
    struct TPMQuote {
        bytes quote; // Raw quote data
        bytes rsaSignature; // RSA signature over the quote
        bytes32[24] pcrs; // PCR values
    }

    /// @notice Decoded RSA public key structure
    struct AkPub {
        uint32 exponentRaw; // RSA exponent (0 represents default 65537)
        bytes modulusRaw; // RSA modulus
    }

    /// @notice Minimal attestation structure
    struct Attestation {
        TPMQuote tpmQuote; // TPM quote data
    }

    /// @notice Instance information containing attestation reports
    struct InstanceInfo {
        bytes attestationReport; // TDX attestation report
        bytes runtimeData; // Runtime configuration data (JSON)
    }

    /// @notice PCR entry
    struct PCR {
        uint256 index; // PCR index
        bytes32 digest; // PCR digest
    }

    /// @notice Complete attestation document
    struct AttestationDocument {
        Attestation attestation;
        InstanceInfo instanceInfo;
        bytes userData; // User-provided data included in attestation
    }

    /// @notice Trusted input
    /// @param akPub Trusted attestation key public key to verify against
    /// @param runtimeDataHash Trusted runtime data hash to verify against
    struct TrustedInput {
        AkPub akPub;
        bytes32 runtimeDataHash;
        PCR[] pcrs;
    }

    /// @notice Verification params
    /// @param attestationDocument The attestation document to validate
    /// @param trustedInput Trusted input to verify against
    /// @param nonce Random nonce to prevent replay attacks
    struct VerifyParams {
        AttestationDocument attestationDocument;
        TrustedInput trustedInput;
        bytes nonce;
    }

    /// @notice Verifies an attestation
    /// @param verifyParams The verification params
    /// @return unverifiedTdxQuote The unverified TDX quote
    function verify(VerifyParams memory verifyParams) internal view returns (bytes memory unverifiedTdxQuote) {
        return AzureTDXAttestationDocument.verify(
            verifyParams.attestationDocument, verifyParams.trustedInput, verifyParams.nonce
        );
    }
}

/// @title AzureTDXAttestationDocument
/// @notice Attestation document implementation for Azure TDX attestation
library AzureTDXAttestationDocument {
    using AzureTDXTPMQuote for AzureTDX.TPMQuote;
    using AzureTDXInstanceInfo for AzureTDX.InstanceInfo;

    /// @notice Verifies a complete attestation document
    /// @param attestationDocument The attestation document to validate
    /// @param trustedInput Trusted input to verify against
    /// @param nonce Random nonce to prevent replay attacks
    /// @return unverifiedTdxQuote The unverified TDX quote
    function verify(
        AzureTDX.AttestationDocument memory attestationDocument,
        AzureTDX.TrustedInput memory trustedInput,
        bytes memory nonce
    ) internal view returns (bytes memory unverifiedTdxQuote) {
        AzureTDX.TPMQuote memory tpmQuote = attestationDocument.attestation.tpmQuote;

        // Compute expected nonce values
        bytes32 extraData = _makeExtraData(attestationDocument.userData, nonce);
        bytes32 tpmNonce = _makeTpmNonce(attestationDocument.instanceInfo, extraData);

        // Validate HCL report and verify it matches the attestation key
        attestationDocument.instanceInfo.verify(trustedInput);

        // Verify the TPM attestation
        tpmQuote.verify(trustedInput.akPub, trustedInput.pcrs, tpmNonce);

        unverifiedTdxQuote = attestationDocument.instanceInfo.attestationReport;
    }

    /// @notice Creates extra data hash from user data and nonce
    /// @param userData User-provided data
    /// @param nonce Random nonce
    /// @return Hash of concatenated user data and nonce
    function _makeExtraData(bytes memory userData, bytes memory nonce) private pure returns (bytes32) {
        return sha256(abi.encodePacked(userData, nonce));
    }

    /// @notice Creates TPM nonce from instance info and extra data in the
    /// Constellation format
    /// @param instanceInfo Instance information containing reports
    /// @param extraData Extra data hash
    /// @return TPM nonce
    function _makeTpmNonce(AzureTDX.InstanceInfo memory instanceInfo, bytes32 extraData)
        private
        pure
        returns (bytes32)
    {
        // Below is a slightly more fun and unsafe version of the below code.
        // ```Solidity
        // bytes(abi.encodePacked(
        //     "{\"AttestationReport\":\"",
        //     Base64.encode(instanceInfo.attestationReport),
        //     "\",\"RuntimeData\":\"",
        //     Base64.encode(instanceInfo.runtimeData),
        //     "\"}",
        //     extraData
        // ))
        // ```
        // This saves about 20k gas.

        // Calculate the length of the Base64 encoded strings
        uint256 attestationReportB64Length = 4 * ((instanceInfo.attestationReport.length + 2) / 3);
        uint256 runtimeDataB64Length = 4 * ((instanceInfo.runtimeData.length + 2) / 3);

        // Calculate the total length of the resulting string
        // len("{\"AttestationReport\":\"") == 22
        // len("\",\"RuntimeData\":\"") == 17
        // len("\"}") == 2
        // len(extraData) == 32
        uint256 finalLength = 22 + attestationReportB64Length + 17 + runtimeDataB64Length + 2 + 32;

        // Allocate the string
        string memory result = new string(finalLength);

        // Secure the current free memory pointer
        uint256 fmp;
        assembly {
            fmp := mload(0x40)
        }

        // Set the offset to where the B64 string will be written
        uint256 offset = 22;

        // Set the free memory pointer to the start of the string
        assembly {
            mstore(0x40, add(result, offset))
        }

        // Write the attestation report B64 string
        Base64.encode(instanceInfo.attestationReport);

        // Write the attestation report prefix string overriding the length part
        assembly {
            let attestationReportPrefix := 0x7b224174746573746174696f6e5265706f7274223a22 // "{\"AttestationReport\":\""
            mstore(add(result, offset), attestationReportPrefix)
            mstore(result, finalLength)
        }

        // Write the runtime data B64 string
        unchecked {
            offset += 0x20 + attestationReportB64Length;
        }
        assembly {
            let runtimePrefix := shl(120, 0x222c2252756e74696d6544617461223a22) // "\",\"RuntimeData\":\""
            mstore(add(result, offset), runtimePrefix)
        }

        unchecked {
            offset += 17;
        }

        // Write the runtime data prefix string securing and restoring what will be its length slot
        uint256 tmp;
        assembly {
            mstore(0x40, add(result, sub(offset, 0x20)))
            tmp := mload(add(result, sub(offset, 0x20)))
        }
        Base64.encode(instanceInfo.runtimeData);
        assembly {
            mstore(add(result, sub(offset, 0x20)), tmp)
        }

        unchecked {
            offset += runtimeDataB64Length;
        }

        // Write the runtime data suffix string and extra data
        assembly {
            let runtimePrefix := shl(240, 0x227d) // "\"}"
            mstore(add(result, offset), runtimePrefix)

            offset := add(offset, 2)

            mstore(add(result, offset), extraData)
        }

        // Restore the free memory pointer
        assembly {
            mstore(0x40, fmp)
        }

        return sha256(bytes(result));
    }
}

/// @title AzureTDXInstanceInfo
/// @notice Instance information implementation for Azure TDX attestation
library AzureTDXInstanceInfo {
    /// @notice Verifies an instance information
    /// @param instanceInfo The instance information to verify
    /// @param trustedInput The trusted input to verify against
    function verify(AzureTDX.InstanceInfo memory instanceInfo, AzureTDX.TrustedInput memory trustedInput)
        internal
        pure
    {
        _verifyHclReport(instanceInfo, trustedInput);
    }

    /// @notice Validates HCL report JSON and verifies it contains the correct AK public key
    /// @param instanceInfo The instance information containing the runtime data
    /// @param trustedInput The trusted input to verify against
    function _verifyHclReport(AzureTDX.InstanceInfo memory instanceInfo, AzureTDX.TrustedInput memory trustedInput)
        private
        pure
    {
        // Verify SHA256 hash of runtimeData matches beginning of reportData
        bytes32 runtimeDataHash = sha256(instanceInfo.runtimeData);
        bytes32 reportDataPrefix = _extractReportDataPrefix(instanceInfo.attestationReport);

        if (runtimeDataHash != reportDataPrefix) {
            revert AzureTDXErrors.AttestationReportHashMismatch(runtimeDataHash, reportDataPrefix);
        }

        if (runtimeDataHash != trustedInput.runtimeDataHash) {
            revert AzureTDXErrors.RuntimeDataHashMismatch(runtimeDataHash, trustedInput.runtimeDataHash);
        }
    }

    /// @notice Extracts report data from a TDX quote
    /// @param quote The TDX quote containing the report data
    /// @return reportDataPrefix The extracted report data prefix
    function _extractReportDataPrefix(bytes memory quote) private pure returns (bytes32 reportDataPrefix) {
        if (quote.length < AzureTDXConstants.TDX_REPORT_DATA_OFFSET + AzureTDXConstants.TDX_REPORT_DATA_SIZE) {
            revert AzureTDXErrors.QuoteTooShort(
                quote.length, AzureTDXConstants.TDX_REPORT_DATA_OFFSET + AzureTDXConstants.TDX_REPORT_DATA_SIZE
            );
        }

        uint256 offset = AzureTDXConstants.TDX_REPORT_DATA_OFFSET;

        /// @solidity memory-safe-assembly
        assembly {
            reportDataPrefix := mload(add(quote, add(0x20, offset)))
        }
    }
}

/// @title AzureTDXTPMQuote
/// @notice TPM quote implementation for Azure TDX attestation
library AzureTDXTPMQuote {
    using AzureTDXAkPub for AzureTDX.AkPub;

    /// @notice Verifies a TPM quote structure and signature
    /// @param tpmQuote The TPM quote to verify
    /// @param akPub The attestation key public key
    /// @param tpmNonce Expected nonce value in the quote
    function verify(
        AzureTDX.TPMQuote memory tpmQuote,
        AzureTDX.AkPub memory akPub,
        AzureTDX.PCR[] memory pcrs,
        bytes32 tpmNonce
    ) internal view {
        validate(tpmQuote, pcrs, tpmNonce);

        akPub.verifySignature(tpmQuote.rsaSignature, tpmQuote.quote);
    }

    /// @notice Validates a TPM quote structure
    /// @param tpmQuote The TPM quote to verify
    /// @param tpmNonce Expected nonce value in the quote
    function validate(AzureTDX.TPMQuote memory tpmQuote, AzureTDX.PCR[] memory pcrs, bytes32 tpmNonce) internal pure {
        _validateHeader(tpmQuote, tpmNonce);
        _validatePCRs(tpmQuote, pcrs);
    }

    /// @notice Validates the TPM header
    /// @param tpmQuote The TPM quote to verify
    function _validateHeader(AzureTDX.TPMQuote memory tpmQuote, bytes32 tpmNonce) private pure {
        bytes memory quoteData = tpmQuote.quote;
        uint256 quoteDataStart;
        /// @solidity memory-safe-assembly
        assembly {
            quoteDataStart := add(quoteData, 0x20)
        }

        if (quoteData.length < AzureTDXConstants.QUOTE_HEADER_SIZE) {
            revert AzureTDXErrors.QuoteTooShort(quoteData.length, AzureTDXConstants.QUOTE_HEADER_SIZE);
        }

        uint256 offset = 0;

        uint32 magic;
        /// @solidity memory-safe-assembly
        assembly {
            magic := shr(224, mload(add(quoteDataStart, offset)))
        }

        if (magic != AzureTDXConstants.TPMS_GENERATED_VALUE) {
            revert AzureTDXErrors.InvalidMagicValue(magic, AzureTDXConstants.TPMS_GENERATED_VALUE);
        }

        unchecked {
            offset += 4;
        }

        uint16 attestType;
        /// @solidity memory-safe-assembly
        assembly {
            attestType := shr(240, mload(add(quoteDataStart, offset)))
        }

        if (attestType != AzureTDXConstants.TAG_ATTEST_QUOTE) {
            revert AzureTDXErrors.InvalidAttestationType(attestType, AzureTDXConstants.TAG_ATTEST_QUOTE);
        }

        unchecked {
            offset += 2;
        }

        uint16 nameLen;
        /// @solidity memory-safe-assembly
        assembly {
            nameLen := shr(240, mload(add(quoteDataStart, offset)))
        }

        unchecked {
            offset += 2 + nameLen;
        }

        uint16 extraDataLen;
        /// @solidity memory-safe-assembly
        assembly {
            extraDataLen := shr(240, mload(add(quoteDataStart, offset)))
        }

        if (extraDataLen != AzureTDXConstants.TPM_NONCE_SIZE) {
            revert AzureTDXErrors.InvalidExtraDataLength(extraDataLen, AzureTDXConstants.TPM_NONCE_SIZE);
        }

        unchecked {
            offset += 2;
        }
        bytes32 extraData;
        /// @solidity memory-safe-assembly
        assembly {
            extraData := mload(add(quoteDataStart, offset))
        }
        if (extraData != tpmNonce) {
            revert AzureTDXErrors.ExtraDataMismatch(extraData, tpmNonce);
        }
    }

    /// @notice Validates PCR values match the digest in the quote
    /// @dev These values could be checked a bit more efficiently by reading
    /// the entire slot, masking it and comparing to a reference.
    /// Done individually for better error throwing.
    /// @param tpmQuote The TPM quote containing PCR information
    function _validatePCRs(AzureTDX.TPMQuote memory tpmQuote, AzureTDX.PCR[] memory pcrs) private pure {
        // Parse quote to extract PCR digest for comparison
        bytes memory quoteData = tpmQuote.quote;
        uint256 quoteDataStart;
        /// @solidity memory-safe-assembly
        assembly {
            quoteDataStart := add(quoteData, 0x20)
        }

        uint256 offset = AzureTDXConstants.QUOTE_HEADER_SIZE;

        // Skip QualifiedSigner
        /// @solidity memory-safe-assembly
        assembly {
            let nameLen := shr(240, mload(add(quoteDataStart, offset)))
            offset := add(offset, add(2, nameLen))
        }

        // Skip ExtraData, ClockInfo and FirmwareVersion
        unchecked {
            offset += (2 + AzureTDXConstants.TPM_NONCE_SIZE) + AzureTDXConstants.CLOCK_INFO_SIZE
                + AzureTDXConstants.FIRMWARE_VERSION_SIZE;
        }

        uint32 pcrSelectionCount;
        uint16 hashAlgo;
        uint32 pcrBitmap;
        uint256 pcrDigestLen;
        bytes32 pcrDigest;
        uint256 sizeOfBitmap;

        // Parse PCR selection and digest
        /// @solidity memory-safe-assembly
        assembly {
            pcrSelectionCount := shr(224, mload(add(quoteDataStart, offset)))
            offset := add(offset, 4)

            hashAlgo := shr(240, mload(add(quoteDataStart, offset)))
            offset := add(offset, 2)

            sizeOfBitmap := shr(248, mload(add(quoteDataStart, offset)))
            offset := add(offset, 1)

            if gt(sizeOfBitmap, 0) {
                pcrBitmap := shr(sub(256, mul(sizeOfBitmap, 8)), mload(add(quoteDataStart, offset)))
            }
            offset := add(offset, sizeOfBitmap)

            pcrDigestLen := shr(240, mload(add(quoteDataStart, offset)))
            offset := add(offset, 2)

            pcrDigest := mload(add(quoteDataStart, offset))
        }

        if (pcrSelectionCount != 1) {
            revert AzureTDXErrors.InvalidPCRSelectionCount(pcrSelectionCount, 1);
        }

        if (hashAlgo != 11) {
            revert AzureTDXErrors.InvalidHashAlgorithm(hashAlgo, 11);
        }

        if (pcrBitmap != AzureTDXConstants.EXPECTED_PCR_BITMAP) {
            revert AzureTDXErrors.InvalidPCRBitmap(pcrBitmap, AzureTDXConstants.EXPECTED_PCR_BITMAP);
        }

        if (pcrDigestLen != AzureTDXConstants.SHA256_DIGEST_SIZE) {
            revert AzureTDXErrors.InvalidPCRDigestLength(pcrDigestLen, AzureTDXConstants.SHA256_DIGEST_SIZE);
        }

        if (pcrDigest != sha256(abi.encodePacked(tpmQuote.pcrs))) {
            revert AzureTDXErrors.PCRDigestMismatch(pcrDigest, sha256(abi.encodePacked(tpmQuote.pcrs)));
        }

        uint256 pcrsBitmap = 0;
        for (uint256 i = 0; i < pcrs.length; i++) {
            uint256 index = pcrs[i].index;
            if (index >= AzureTDXConstants.PCR_COUNT) {
                revert AzureTDXErrors.InvalidPCRIndex(index);
            }

            if (pcrsBitmap & (1 << index) != 0) {
                revert AzureTDXErrors.DuplicatePCR(index);
            }

            pcrsBitmap |= 1 << index;

            if (pcrs[i].digest != tpmQuote.pcrs[index]) {
                revert AzureTDXErrors.PCRMismatch(i);
            }
        }
    }
}

/// @title AzureTDXAkPub
/// @notice Attestation key public key implementation for Azure TDX attestation
library AzureTDXAkPub {
    /// @notice Verifies a signature over a message
    /// @param signature The signature to verify
    /// @param akPub The attestation key public key
    /// @param message The message that was signed
    function verifySignature(AzureTDX.AkPub memory akPub, bytes memory signature, bytes memory message) internal view {
        uint32 exponent = akPub.exponentRaw == 0 ? AzureTDXConstants.DEFAULT_RSA_EXPONENT : akPub.exponentRaw;

        if (!RSA.pkcs1Sha256(message, signature, abi.encodePacked(exponent), akPub.modulusRaw)) {
            revert AzureTDXErrors.InvalidSignature();
        }
    }
}
