// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Base64} from "solady/utils/Base64.sol";
import {RSA} from "openzeppelin-contracts/contracts/utils/cryptography/RSA.sol";

/// @title AzureTDXErrors
/// @notice Error definitions for Azure TDX attestation validation
library AzureTDXErrors {
    /// @dev Selector: 0x275d88f5
    error InvalidMagicValue(uint32 actual, uint32 expected);
    /// @dev Selector: 0xe2c91f07
    error InvalidAttestationType(uint16 actual, uint16 expected);
    /// @dev Selector: 0x582d9d9e
    error InvalidExtraDataLength(uint16 actual, uint16 expected);
    /// @dev Selector: 0xe732c100
    error InvalidPCRDigestLength(uint256 actual, uint256 expected);
    /// @dev Selector: 0xbd30298c
    error InvalidPCRSelectionCount(uint32 actual, uint32 expected);
    /// @dev Selector: 0x04a788cd
    error InvalidPCRBitmap(uint32 actual, uint32 expected);
    /// @dev Selector: 0x49909b94
    error PCRDigestMismatch(bytes32 actual, bytes32 expected);
    /// @dev Selector: 0x79845059
    error ExtraDataMismatch(bytes32 actual, bytes32 expected);
    /// @dev Selector: 0x4638579c
    error AttestationReportHashMismatch(bytes32 actual, bytes32 expected);
    /// @dev Selector: 0xf8f24d74
    error DuplicatePCR(uint256 index);
    /// @dev Selector: 0x53e619a0
    error InvalidPCRIndex(uint256 index, uint256 bitmap);
    /// @dev Selector: 0xceb66952
    error PCRMismatch(uint256 entryIndex);
    /// @dev Selector: 0x0d59ee32
    error QuoteTooShort(uint256 actual, uint256 required);
    /// @dev Selector: 0x4e2132b9
    error InvalidHashAlgorithm(uint16 actual, uint16 expected);
    /// @dev Selector: 0x8baa579f
    error InvalidSignature();
    /// @dev Selector: 0x5c48d84b
    error InvalidRuntimeData();
}

/// @title AzureTDXConstants
/// @notice Constants for Azure TDX attestation validation
library AzureTDXConstants {
    // TPM Quote Constants
    uint32 internal constant TPMS_GENERATED_VALUE = 0xff544347;
    uint16 internal constant TAG_ATTEST_QUOTE = 0x8018;
    uint16 internal constant ALG_SHA256 = 0x000b;

    // Structure sizes
    uint256 internal constant QUOTE_HEADER_SIZE = 6; // magic(4) + type(2)
    uint256 internal constant CLOCK_INFO_SIZE = 17; // clock(8) + resetCount(4) + restartCount(4) + safe(1)
    uint256 internal constant FIRMWARE_VERSION_SIZE = 8;
    uint256 internal constant SHA256_DIGEST_SIZE = 32;
    uint16 internal constant TPM_NONCE_SIZE = 32;

    // PCR Constants
    uint32 internal constant EXPECTED_PCR_SELECTION_COUNT = 1;
    uint32 internal constant EXPECTED_PCR_BITMAP = 0xffffff; // All 24 PCRs
    uint32 internal constant PCR_COUNT = 24;

    // TDX Quote Constants
    uint256 internal constant TDX_REPORT_DATA_OFFSET = 0x238;
    uint256 internal constant TDX_REPORT_DATA_SIZE = 64;

    // RSA Constants
    uint24 internal constant DEFAULT_RSA_EXPONENT = 65537;
}

/// @title AzureTDX
/// @notice Library for validating Azure TDX attestations with TPM quotes
/// This library is compatible with the Constellation validation standard,
/// relies on some initial pre-processing to remove unnecessary data and
/// takes some assumptions over the data instead of doing a full sanity
/// check, such as the some field sizes. It also doesn't verify the event logs
/// result on the expected PCRs.
/// The TDX quote is not verified - it is expected to be verified by the
/// caller through external means.
library AzureTDX {
    /// @notice Minimal TPM quote structure containing only required fields
    struct TPMQuote {
        bytes quote; // Raw quote data
        bytes rsaSignature; // RSA signature over the quote
        bytes32[24] pcrs; // PCR values
    }

    /// @notice Decoded RSA public key structure
    struct AkPub {
        uint24 exponentRaw; // RSA exponent (0 represents default 65537)
        bytes modulusRaw; // RSA modulus
    }

    /// @notice Minimal attestation structure
    struct Attestation {
        TPMQuote tpmQuote; // TPM quote data
    }

    /// @notice Runtime data structure
    struct RuntimeData {
        bytes raw; // Runtime configuration data (JSON)
        AkPub hclAkPub; // HCL attestation public key
    }

    /// @notice Instance information containing attestation reports
    struct InstanceInfo {
        bytes attestationReport; // TDX attestation report
        RuntimeData runtimeData; // Runtime data
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

    /// @notice Verification params
    /// @param attestationDocument The attestation document to validate
    /// @param pcrs PCRs to verify against
    /// @param nonce Random nonce to prevent replay attacks
    struct VerifyParams {
        AttestationDocument attestationDocument;
        PCR[] pcrs;
        bytes nonce;
    }

    /// @notice Verifies an attestation
    /// @param verifyParams The verification params
    /// @return unverifiedTdxQuote The unverified TDX quote
    function verify(VerifyParams memory verifyParams) internal view returns (bytes memory unverifiedTdxQuote) {
        return
            AzureTDXAttestationDocument.verify(verifyParams.attestationDocument, verifyParams.pcrs, verifyParams.nonce);
    }
}

/// @title AzureTDXAttestationDocument
/// @notice Attestation document implementation for Azure TDX attestation
library AzureTDXAttestationDocument {
    using AzureTDXTPMQuote for AzureTDX.TPMQuote;
    using AzureTDXInstanceInfo for AzureTDX.InstanceInfo;

    /// @notice Verifies a complete attestation document
    /// @param attestationDocument The attestation document to validate
    /// @param pcrs PCRs to verify against
    /// @param nonce Nonce used in the attestation issuing
    /// @return unverifiedTdxQuote The unverified TDX quote
    function verify(
        AzureTDX.AttestationDocument memory attestationDocument,
        AzureTDX.PCR[] memory pcrs,
        bytes memory nonce
    ) internal view returns (bytes memory unverifiedTdxQuote) {
        AzureTDX.TPMQuote memory tpmQuote = attestationDocument.attestation.tpmQuote;

        // Compute expected nonce values
        bytes32 extraData = _makeExtraData(attestationDocument.userData, nonce);
        bytes32 tpmNonce = _makeTpmNonce(attestationDocument.instanceInfo, extraData);

        // Validate HCL report
        attestationDocument.instanceInfo.verify();

        // Verify the TPM attestation
        tpmQuote.verify(attestationDocument.instanceInfo.runtimeData.hclAkPub, pcrs, tpmNonce);

        unverifiedTdxQuote = attestationDocument.instanceInfo.attestationReport;
    }

    /// @notice Creates extra data hash from user data and nonce
    /// @param userData User-provided data
    /// @param nonce Random nonce
    /// @return extraData Hash of concatenated user data and nonce
    function _makeExtraData(bytes memory userData, bytes memory nonce) private view returns (bytes32 extraData) {
        bytes memory content = abi.encodePacked(userData, nonce);
        /// @solidity memory-safe-assembly
        assembly {
            let success := staticcall(gas(), 0x02, add(content, 0x20), mload(content), 0x00, 0x20)
            if iszero(success) { revert(0, 0) }
            extraData := mload(0x00)
        }
    }

    /// @notice Creates TPM nonce from instance info and extra data in the
    /// Constellation format
    /// @param instanceInfo Instance information containing reports
    /// @param extraData Extra data hash
    /// @return tpmNonce TPM nonce
    function _makeTpmNonce(AzureTDX.InstanceInfo memory instanceInfo, bytes32 extraData)
        private
        view
        returns (bytes32 tpmNonce)
    {
        // Compiling this with solc 0.8.28, the result is actually very
        // efficient.
        // The difference from encoding it like this versus pre-allocating the
        // string and manipulating the FMP to fill it is about 400 gas only,
        // even if it feels like this would lead to way more gas usage.
        // forgefmt: disable-next-item
        bytes memory content = bytes(abi.encodePacked(
            "{\"AttestationReport\":\"",
            Base64.encode(instanceInfo.attestationReport),
            "\",\"RuntimeData\":\"",
            Base64.encode(instanceInfo.runtimeData.raw),
            "\"}",
            extraData
        ));
        /// @solidity memory-safe-assembly
        assembly {
            let success := staticcall(gas(), 0x02, add(content, 0x20), mload(content), 0x00, 0x20)
            if iszero(success) { revert(0, 0) }
            tpmNonce := mload(0x00)
        }
    }
}

/// @title AzureTDXInstanceInfo
/// @notice Instance information implementation for Azure TDX attestation
library AzureTDXInstanceInfo {
    using AzureTDXRuntimeData for AzureTDX.RuntimeData;

    /// @notice Verifies an instance information
    /// @param instanceInfo The instance information to verify
    function verify(AzureTDX.InstanceInfo memory instanceInfo) internal view {
        _verifyHclReport(instanceInfo);
    }

    /// @notice Validates HCL report JSON and verifies it contains the correct AK public key
    /// @param instanceInfo The instance information containing the runtime data
    function _verifyHclReport(AzureTDX.InstanceInfo memory instanceInfo) private view {
        AzureTDX.RuntimeData memory runtimeData = instanceInfo.runtimeData;
        runtimeData.validate();

        bytes32 reportDataHash = runtimeData.hash();
        bytes32 reportDataHashQuotePrefix = _extractReportDataHashQuotePrefix(instanceInfo.attestationReport);

        if (reportDataHash != reportDataHashQuotePrefix) {
            revert AzureTDXErrors.AttestationReportHashMismatch(reportDataHash, reportDataHashQuotePrefix);
        }
    }

    /// @notice Extracts report data hash quote prefix from a TDX quote
    /// @param quote The TDX quote containing the quote hash as a prefix
    /// @return quotePrefix The extracted quote prefix
    function _extractReportDataHashQuotePrefix(bytes memory quote) private pure returns (bytes32 quotePrefix) {
        if (quote.length < AzureTDXConstants.TDX_REPORT_DATA_OFFSET + AzureTDXConstants.TDX_REPORT_DATA_SIZE) {
            revert AzureTDXErrors.QuoteTooShort(
                quote.length, AzureTDXConstants.TDX_REPORT_DATA_OFFSET + AzureTDXConstants.TDX_REPORT_DATA_SIZE
            );
        }

        uint256 offset = AzureTDXConstants.TDX_REPORT_DATA_OFFSET;

        /// @solidity memory-safe-assembly
        assembly {
            quotePrefix := mload(add(quote, add(0x20, offset)))
        }
    }
}

/// @title AzureTDXRuntimeData
/// @notice Runtime data implementation for Azure TDX attestation
library AzureTDXRuntimeData {
    using AzureTDXAkPub for AzureTDX.AkPub;

    /// @notice Validates the runtime data
    /// @param runtimeData The runtime data to validate
    function validate(AzureTDX.RuntimeData memory runtimeData) internal pure {
        AzureTDX.AkPub memory hclAkPub = runtimeData.hclAkPub;
        bytes memory raw = runtimeData.raw;

        (bytes32 expectedPrefixHash, uint256 expectedPrefixLen) = _computeExpectedPrefix(hclAkPub);

        if (runtimeData.raw.length < expectedPrefixLen) {
            revert AzureTDXErrors.InvalidRuntimeData();
        }

        bytes32 runtimeDataRawPrefixHash;
        /// @solidity memory-safe-assembly
        assembly {
            runtimeDataRawPrefixHash := keccak256(add(raw, 0x20), expectedPrefixLen)
        }

        if (runtimeDataRawPrefixHash != expectedPrefixHash) {
            revert AzureTDXErrors.InvalidRuntimeData();
        }
    }

    /// @notice Computes the raw report data hash
    /// @param runtimeData The runtime data to compute the hash from
    /// @return runtimeDataHash The computed runtime data hash
    function hash(AzureTDX.RuntimeData memory runtimeData) internal view returns (bytes32 runtimeDataHash) {
        bytes memory raw = runtimeData.raw;
        /// @solidity memory-safe-assembly
        assembly {
            let success := staticcall(gas(), 0x02, add(raw, 0x20), mload(raw), 0x00, 0x20)
            if iszero(success) { revert(0, 0) }
            runtimeDataHash := mload(0x00)
        }
    }

    function _computeExpectedPrefix(AzureTDX.AkPub memory hclAkPub)
        private
        pure
        returns (bytes32 expectedPrefixHash, uint256 expectedPrefixLen)
    {
        uint24 exponent = hclAkPub.exponentRaw == 0 ? AzureTDXConstants.DEFAULT_RSA_EXPONENT : hclAkPub.exponentRaw;

        bytes memory prefix = bytes(
            string.concat(
                "{\"keys\":[{\"kid\":\"HCLAkPub\",\"key_ops\":[\"sign\"],\"kty\":\"RSA\",\"e\":\"",
                Base64.encode(abi.encodePacked(exponent), true, true),
                "\",\"n\":\"",
                Base64.encode(hclAkPub.modulusRaw, true, true),
                "\"}"
            )
        );

        expectedPrefixHash = keccak256(prefix);
        expectedPrefixLen = prefix.length;
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
    function validate(AzureTDX.TPMQuote memory tpmQuote, AzureTDX.PCR[] memory pcrs, bytes32 tpmNonce) internal view {
        _validateHeader(tpmQuote, tpmNonce);
        _validatePCRs(tpmQuote, pcrs);
    }

    /// @notice Validates the TPM header
    /// @param tpmQuote The TPM quote to verify
    function _validateHeader(AzureTDX.TPMQuote memory tpmQuote, bytes32 tpmNonce) private pure {
        bytes memory quoteData = tpmQuote.quote;
        uint256 quoteDataCursor;
        /// @solidity memory-safe-assembly
        assembly {
            quoteDataCursor := add(quoteData, 0x20)
        }

        if (quoteData.length < AzureTDXConstants.QUOTE_HEADER_SIZE) {
            revert AzureTDXErrors.QuoteTooShort(quoteData.length, AzureTDXConstants.QUOTE_HEADER_SIZE);
        }

        uint32 magic;
        uint16 attestType;
        uint16 nameLen;
        uint16 extraDataLen;
        bytes32 extraData;

        // Read all header values in assembly
        /// @solidity memory-safe-assembly
        assembly {
            let data := mload(quoteDataCursor)

            magic := shr(224, data)
            attestType := and(shr(208, data), 0xffff)
            nameLen := and(shr(192, data), 0xffff)
            quoteDataCursor := add(quoteDataCursor, add(8, nameLen))
            data := mload(quoteDataCursor)
            extraDataLen := shr(240, data)
            extraData := mload(add(quoteDataCursor, 2))
        }

        if (magic != AzureTDXConstants.TPMS_GENERATED_VALUE) {
            revert AzureTDXErrors.InvalidMagicValue(magic, AzureTDXConstants.TPMS_GENERATED_VALUE);
        }

        if (attestType != AzureTDXConstants.TAG_ATTEST_QUOTE) {
            revert AzureTDXErrors.InvalidAttestationType(attestType, AzureTDXConstants.TAG_ATTEST_QUOTE);
        }

        if (extraDataLen != AzureTDXConstants.TPM_NONCE_SIZE) {
            revert AzureTDXErrors.InvalidExtraDataLength(extraDataLen, AzureTDXConstants.TPM_NONCE_SIZE);
        }

        if (extraData != tpmNonce) {
            revert AzureTDXErrors.ExtraDataMismatch(extraData, tpmNonce);
        }
    }

    /// @notice Validates PCR values match the digest in the quote
    /// @dev Optimized to reduce mload operations by combining reads and reusing values
    /// @param tpmQuote The TPM quote containing PCR information
    function _validatePCRs(AzureTDX.TPMQuote memory tpmQuote, AzureTDX.PCR[] memory pcrs) private view {
        // Parse quote to extract PCR digest for comparison
        bytes memory quoteData = tpmQuote.quote;
        uint256 quoteDataCursor;

        /// @solidity memory-safe-assembly
        assembly {
            quoteDataCursor := add(quoteData, 0x20)
        }

        unchecked {
            quoteDataCursor += AzureTDXConstants.QUOTE_HEADER_SIZE;
        }

        // Skip QualifiedSigner - combine length read with cursor update
        /// @solidity memory-safe-assembly
        assembly {
            let data := mload(quoteDataCursor)
            let nameLen := shr(240, data)
            quoteDataCursor := add(quoteDataCursor, add(2, nameLen))
        }

        // Skip ExtraData, ClockInfo and FirmwareVersion
        unchecked {
            quoteDataCursor += (2 + AzureTDXConstants.TPM_NONCE_SIZE) + AzureTDXConstants.CLOCK_INFO_SIZE
                + AzureTDXConstants.FIRMWARE_VERSION_SIZE;
        }

        uint32 pcrSelectionCount;
        uint16 hashAlgo;
        uint32 pcrBitmap;
        uint256 pcrDigestLen;
        bytes32 pcrDigest;

        // Parse PCR selection and digest - optimize by reading larger chunks
        /// @solidity memory-safe-assembly
        assembly {
            let data := mload(quoteDataCursor)
            pcrSelectionCount := shr(224, data)
            hashAlgo := and(shr(208, data), 0xffff)
            let sizeOfBitmap := byte(6, data)
            if gt(sizeOfBitmap, 4) { revert(0, 0) }
            let sizeOfBitmapShifted := shl(3, sizeOfBitmap)
            pcrBitmap := and(shr(sub(200, sizeOfBitmapShifted), data), sub(shl(sizeOfBitmapShifted, 1), 1))
            pcrDigestLen := and(shr(sub(184, sizeOfBitmapShifted), data), 0xffff)
            pcrDigest := mload(add(quoteDataCursor, add(9, sizeOfBitmap)))
        }

        // Validation checks
        if (pcrSelectionCount != AzureTDXConstants.EXPECTED_PCR_SELECTION_COUNT) {
            revert AzureTDXErrors.InvalidPCRSelectionCount(
                pcrSelectionCount, AzureTDXConstants.EXPECTED_PCR_SELECTION_COUNT
            );
        }

        if (hashAlgo != AzureTDXConstants.ALG_SHA256) {
            revert AzureTDXErrors.InvalidHashAlgorithm(hashAlgo, AzureTDXConstants.ALG_SHA256);
        }

        if (pcrBitmap != AzureTDXConstants.EXPECTED_PCR_BITMAP) {
            revert AzureTDXErrors.InvalidPCRBitmap(pcrBitmap, AzureTDXConstants.EXPECTED_PCR_BITMAP);
        }

        if (pcrDigestLen != AzureTDXConstants.SHA256_DIGEST_SIZE) {
            revert AzureTDXErrors.InvalidPCRDigestLength(pcrDigestLen, AzureTDXConstants.SHA256_DIGEST_SIZE);
        }

        bytes32[24] memory quotePcrs = tpmQuote.pcrs;
        bytes32 computedPcrDigest;
        /// @solidity memory-safe-assembly
        assembly {
            let success := staticcall(gas(), 0x02, quotePcrs, 768, 0x00, 0x20)
            if iszero(success) { revert(0, 0) }
            computedPcrDigest := mload(0x00)
        }

        if (pcrDigest != computedPcrDigest) {
            revert AzureTDXErrors.PCRDigestMismatch(pcrDigest, computedPcrDigest);
        }

        // Validate individual PCRs
        uint256 comparedPcrsBitmap = 0;
        uint256 pcrsLength = pcrs.length;

        for (uint256 i = 0; i < pcrsLength;) {
            uint256 index = pcrs[i].index;
            uint256 mask = 1 << index;

            if (pcrBitmap & mask == 0) {
                revert AzureTDXErrors.InvalidPCRIndex(index, pcrBitmap);
            }

            if (comparedPcrsBitmap & mask != 0) {
                revert AzureTDXErrors.DuplicatePCR(index);
            }

            comparedPcrsBitmap |= mask;

            if (pcrs[i].digest != tpmQuote.pcrs[index]) {
                revert AzureTDXErrors.PCRMismatch(i);
            }

            unchecked {
                ++i;
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
        uint24 exponent = akPub.exponentRaw == 0 ? AzureTDXConstants.DEFAULT_RSA_EXPONENT : akPub.exponentRaw;

        bytes32 messageHash;
        /// @solidity memory-safe-assembly
        assembly {
            let success := staticcall(gas(), 0x02, add(message, 0x20), mload(message), 0x00, 0x20)
            if iszero(success) { revert(0, 0) }
            messageHash := mload(0x00)
        }

        if (!RSA.pkcs1Sha256(messageHash, signature, abi.encodePacked(exponent), akPub.modulusRaw)) {
            revert AzureTDXErrors.InvalidSignature();
        }
    }
}
