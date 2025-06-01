// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Base64} from "solady/utils/Base64.sol";
import {RSA} from "openzeppelin-contracts/contracts/utils/cryptography/RSA.sol";

/// @title AzureTDXErrors
/// @notice Error definitions for Azure TDX attestation validation
library AzureTDXErrors {
    error ExponentMismatch(uint32 actual, uint32 expected);
    error ModulusLengthMismatch(uint256 actual, uint256 expected);
    error ModulusMismatch();
    error InvalidMagicValue(uint32 actual, uint32 expected);
    error InvalidAttestationType(uint16 actual, uint16 expected);
    error InvalidExtraDataLength(uint16 actual, uint16 expected);
    error InvalidPCRDigestLength(uint256 actual, uint256 expected);
    error InvalidPCRSelectionCount(uint32 actual, uint32 expected);
    error InvalidPCRBitmap(uint32 actual, uint32 expected);
    error PCRDigestMismatch(bytes32 actual, bytes32 expected);
    error RuntimeDataHashMismatch(bytes32 actual, bytes32 expected);
    error InvalidJSONStructure();
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
    uint256 internal constant QUOTE_HEADER_SIZE = 6; // magic(4) + type(2)
    uint256 internal constant CLOCK_INFO_SIZE = 17; // clock(8) + resetCount(4) + restartCount(4) + safe(1)
    uint256 internal constant FIRMWARE_VERSION_SIZE = 8;
    uint256 internal constant SHA256_DIGEST_SIZE = 32;
    uint16 internal constant TPM_NONCE_SIZE = 32;

    // PCR Constants
    uint32 internal constant EXPECTED_PCR_BITMAP = 0xffffff; // All 24 PCRs

    // TDX Quote Constants
    uint256 internal constant TDX_REPORT_DATA_OFFSET = 0x238; // Offset of ReportData in TDX quote
    uint256 internal constant TDX_REPORT_DATA_SIZE = 64;

    // JSON parsing constants for HCL report
    bytes32 internal constant RUNTIME_DATA_START_HASH =
        keccak256(bytes("{\"keys\":[{\"kid\":\"HCLAkPub\",\"key_ops\":[\"sign\"],\"kty\":\"RSA\",\"e\":\""));
    uint256 internal constant RUNTIME_DATA_START_LEN = 63;
    uint256 internal constant RSA_EXPONENT_B64_LEN = 4;
    uint256 internal constant RSA_EXPONENT_B64_END_OFFSET = 5; // RSA_EXPONENT_B64_LEN + length('"'), direct as used in assembly
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
        uint32 pcrsBitMap; // Bitmap indicating which PCRs are included
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

    /// @notice Complete attestation document
    struct AttestationDocument {
        Attestation attestation;
        InstanceInfo instanceInfo;
        bytes userData; // User-provided data included in attestation
    }
}

/// @title AzureTDXAttestationDocument
/// @notice Attestation document implementation for Azure TDX attestation
library AzureTDXAttestationDocument {
    using AzureTDXTPMQuote for AzureTDX.TPMQuote;
    using AzureTDXInstanceInfo for AzureTDX.InstanceInfo;

    /// @notice Verifies a complete attestation document
    /// @param attestationDocument The attestation document to validate
    /// @param nonce Random nonce to prevent replay attacks
    /// @param trustedAkPub Trusted attestation key public key to verify against
    /// @return unverifiedTdxQuote The unverified TDX quote
    /// @return pcrs The PCR values from the TDX quote
    function verify(
        AzureTDX.AttestationDocument memory attestationDocument,
        bytes memory nonce,
        AzureTDX.AkPub memory trustedAkPub
    )
        internal
        view
        returns (
            bytes memory unverifiedTdxQuote,
            bytes32[24] memory pcrs
        )
    {
        AzureTDX.TPMQuote memory tpmQuote = attestationDocument.attestation.tpmQuote;

        unverifiedTdxQuote = attestationDocument.instanceInfo.attestationReport;
        pcrs = tpmQuote.pcrs;

        // Compute expected nonce values
        bytes32 extraData = _makeExtraData(attestationDocument.userData, nonce);
        bytes32 tpmNonce = _makeTpmNonce(attestationDocument.instanceInfo, extraData);

        // Validate HCL report and verify it matches the attestation key
        attestationDocument.instanceInfo.verify(trustedAkPub);

        // Verify the TPM attestation
        tpmQuote.verify(trustedAkPub, tpmNonce);
    }

    /// @notice Creates extra data hash from user data and nonce
    /// @param userData User-provided data
    /// @param nonce Random nonce
    /// @return Hash of concatenated user data and nonce
    function _makeExtraData(bytes memory userData, bytes memory nonce) private pure returns (bytes32) {
        return sha256(abi.encodePacked(userData, nonce));
    }

    /// @notice Creates TPM nonce from instance info and extra data
    /// @param instanceInfo Instance information containing reports
    /// @param extraData Extra data hash
    /// @return TPM nonce hash
    function _makeTpmNonce(AzureTDX.InstanceInfo memory instanceInfo, bytes32 extraData) private pure returns (bytes32) {
        return sha256(abi.encodePacked(instanceInfo.attestationReport, instanceInfo.runtimeData, extraData));
    }
}


/// @title AzureTDXInstanceInfo
/// @notice Instance information implementation for Azure TDX attestation
library AzureTDXInstanceInfo {
    /// @notice Verifies an instance information
    /// @param instanceInfo The instance information to verify
    /// @param trustedAkPub The trusted attestation key public key
    function verify(AzureTDX.InstanceInfo memory instanceInfo, AzureTDX.AkPub memory trustedAkPub) internal pure {
        _verifyHclReport(instanceInfo, trustedAkPub);
    }

    /// @notice Validates HCL report JSON and verifies it contains the correct AK public key
    /// @param instanceInfo The instance information containing the runtime data
    /// @param akPub The attestation key to verify against
    function _verifyHclReport(AzureTDX.InstanceInfo memory instanceInfo, AzureTDX.AkPub memory akPub) private pure {
        // Verify SHA256 hash of runtimeData matches beginning of reportData
        bytes32 runtimeDataHash = sha256(instanceInfo.runtimeData);
        bytes32 reportDataPrefix = _extractReportDataPrefix(instanceInfo.attestationReport);

        if (runtimeDataHash != reportDataPrefix) {
            revert AzureTDXErrors.RuntimeDataHashMismatch(runtimeDataHash, reportDataPrefix);
        }

        // Extract public key from JSON without full parsing
        _validateJsonPublicKey(instanceInfo.runtimeData, akPub);
    }

    /// @notice Extracts and validates public key from JSON runtime data
    /// @dev IMPORTANT: This function assumes JSON ordering. It will revert if
    /// the JSON does not start with the form
    /// `{"keys":[{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"...","n":"..."}`
    /// @param runtimeData The JSON data containing the public key
    /// @param akPub The expected attestation key
    function _validateJsonPublicKey(bytes memory runtimeData, AzureTDX.AkPub memory akPub) private pure {
        // For efficiency, we'll use pattern matching instead of full JSON parsing
        // Expected structure: {"keys":[{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"...","n":"..."}, ...]}

        uint256 runtimeDataStart;
        /// @solidity memory-safe-assembly
        assembly {
            runtimeDataStart := add(runtimeData, 0x20)
        }
        
        uint256 offset = AzureTDXConstants.RUNTIME_DATA_START_LEN;

        // First we check that it starts with '{"keys":[{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"'
        bytes32 runtimeDataHash;
        /// @solidity memory-safe-assembly
        assembly {
            runtimeDataHash := keccak256(runtimeDataStart, offset)
        }
        if (runtimeDataHash != AzureTDXConstants.RUNTIME_DATA_START_HASH) {
            revert AzureTDXErrors.InvalidJSONStructure();
        }

        bytes32 exponentB64;

        // Then we extract the exponent from the JSON by looking for the "
        // If we don't find it at runtimeDataStart.readByte(4), we revert
        /// @solidity memory-safe-assembly
        assembly {
            let lookup := mload(add(runtimeDataStart, offset))
            if eq(byte(4, lookup), 0x22) { exponentB64 := and(lookup, shl(224, 0xffffffff)) }
        }
        if (exponentB64 == bytes32(0)) {
            revert AzureTDXErrors.InvalidJSONStructure();
        }

        unchecked {
            offset += AzureTDXConstants.RSA_EXPONENT_B64_END_OFFSET;
        }

        // Then we check that it next contains ',\"n\":"'
        bool hasCorrectKey;
        /// @solidity memory-safe-assembly
        assembly {
            hasCorrectKey := eq(shr(208, mload(add(runtimeDataStart, offset))), 0x2c226e223a22) // ",\"n\":\""
        }
        if (!hasCorrectKey) {
            revert AzureTDXErrors.InvalidJSONStructure();
        }

        unchecked {
            offset += 6;
        }

        // Then we do a fancier lookup for the first " (0x22)
        uint256 nEnd = AzureTDXInternalUtils.indexOfDoubleQuote(runtimeData, offset);

        // Ideally we'd check the rest of the JSON as a constant here

        bytes memory modulusB64 = AzureTDXInternalUtils.destructiveSlice(runtimeData, offset, nEnd);

        // Decode base64 and validate
        _validateDecodedKey(modulusB64, exponentB64, akPub);
    }

    /// @notice Extracts report data from a TDX quote
    /// @param quote The TDX quote containing the report data
    /// @return reportDataPrefix The extracted report data prefix
    function _extractReportDataPrefix(bytes memory quote) private pure returns (bytes32 reportDataPrefix) {
        if (quote.length < AzureTDXConstants.TDX_REPORT_DATA_OFFSET + AzureTDXConstants.TDX_REPORT_DATA_SIZE) {
            revert AzureTDXErrors.QuoteTooShort(quote.length, AzureTDXConstants.TDX_REPORT_DATA_OFFSET + AzureTDXConstants.TDX_REPORT_DATA_SIZE);
        }

        uint256 offset = AzureTDXConstants.TDX_REPORT_DATA_OFFSET;

        /// @solidity memory-safe-assembly
        assembly {
            reportDataPrefix := mload(add(quote, add(0x20, offset)))
        }
    }
    
    /// @notice Validates decoded base64 key components match the attestation key
    /// @param modulusB64 Base64 encoded modulus
    /// @param exponentB64 Base64 encoded exponent
    /// @param akPub Expected attestation key
    function _validateDecodedKey(bytes memory modulusB64, bytes32 exponentB64, AzureTDX.AkPub memory akPub) private pure {
        // Use inline assembly for base64 decoding to save gas
        bytes memory decodedModulus = Base64.decode(string(modulusB64));

        if (decodedModulus.length != akPub.modulusRaw.length) {
            revert AzureTDXErrors.ModulusLengthMismatch(decodedModulus.length, akPub.modulusRaw.length);
        }

        if (keccak256(decodedModulus) != keccak256(akPub.modulusRaw)) {
            revert AzureTDXErrors.ModulusMismatch();
        }

        uint32 exponentFromRuntime = _decodeExponent(exponentB64);

        bool exponentMatches = (exponentFromRuntime == AzureTDXConstants.DEFAULT_RSA_EXPONENT && akPub.exponentRaw == 0)
            || (exponentFromRuntime == akPub.exponentRaw);

        if (!exponentMatches) {
            revert AzureTDXErrors.ExponentMismatch(exponentFromRuntime, akPub.exponentRaw);
        }
    }

    /// @notice Decodes the exponent from base64
    /// @param exponentB64 Base64 encoded exponent
    /// @return Decoded exponent
    function _decodeExponent(bytes32 exponentB64) private pure returns (uint32) {
        // if the exponent is "AQAB" (0x41514142), it is 0
        if (exponentB64 == bytes32(bytes4(0x41514142))) {
            return 0;
        }

        return AzureTDXInternalUtils.decodeBase64Uint32LittleEndian(exponentB64);
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
    function verify(AzureTDX.TPMQuote memory tpmQuote, AzureTDX.AkPub memory akPub, bytes32 tpmNonce) internal view {
        validate(tpmQuote, tpmNonce);
        
        akPub.verifySignature(tpmQuote.rsaSignature, tpmQuote.quote);
    }

    /// @notice Validates a TPM quote structure
    /// @param tpmQuote The TPM quote to verify
    /// @param tpmNonce Expected nonce value in the quote
    function validate(AzureTDX.TPMQuote memory tpmQuote, bytes32 tpmNonce) internal pure {
        _validateHeader(tpmQuote, tpmNonce);
        _validatePCRs(tpmQuote);
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

        // TODO: Enable nonce verification when instanceInfo is used in ABI encoded form
        // unchecked {
        //     offset += 2;
        // }
        // bytes32 extraData;
        // /// @solidity memory-safe-assembly
        // assembly {
        //     extraData := mload(add(quoteDataStart, offset))
        // }
        // if (extraData != tpmNonce) {
        //     revert AzureTDXErrors.ExtraDataMismatch(extraData, tpmNonce);
        // }
    }

    /// @notice Validates PCR values match the digest in the quote
    /// @dev These values could be checked a bit more efficiently by reading
    /// the entire slot, masking it and comparing to a reference.
    /// Done individually for better error throwing.
    /// @param tpmQuote The TPM quote containing PCR information
    function _validatePCRs(AzureTDX.TPMQuote memory tpmQuote) private pure {
        // Verify PCR bitmap
        if (tpmQuote.pcrsBitMap != AzureTDXConstants.EXPECTED_PCR_BITMAP) {
            revert AzureTDXErrors.InvalidPCRBitmap(tpmQuote.pcrsBitMap, AzureTDXConstants.EXPECTED_PCR_BITMAP);
        }

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
            offset += (2 + AzureTDXConstants.TPM_NONCE_SIZE) + AzureTDXConstants.CLOCK_INFO_SIZE + AzureTDXConstants.FIRMWARE_VERSION_SIZE;
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

library AzureTDXInternalUtils {
    /// @notice Finds the first occurrence of a " (0x22) in a bytes array
    /// @param subject The bytes array to search
    /// @param from The index to start searching from
    /// @return result The index of the first occurrence of the byte, or
    /// type(uint256).max if not found
    function indexOfDoubleQuote(bytes memory subject, uint256 from) internal pure returns (uint256 result) {
        result = type(uint256).max;

        uint256 subjectLen = subject.length;

        if (from >= subjectLen) {
            return result;
        }

        /// @solidity memory-safe-assembly
        assembly {
            let subjectData := add(subject, 0x20)
            let searchPtr := add(subjectData, from)
            let endPtr := add(subjectData, subjectLen)

            for {} lt(searchPtr, endPtr) { searchPtr := add(searchPtr, 0x20) } {
                let chunk := mload(searchPtr)
                let xored := xor(chunk, 0x2222222222222222222222222222222222222222222222222222222222222222) // " is 0x22

                // Use bit manipulation to find zero bytes
                // (x - 0x01010101...) & ~x & 0x80808080... will have 0x80 bits set where bytes are 0
                let zeros :=
                    and(
                        and(sub(xored, 0x0101010101010101010101010101010101010101010101010101010101010101), not(xored)),
                        0x8080808080808080808080808080808080808080808080808080808080808080
                    )

                if zeros {
                    for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                        if iszero(byte(i, xored)) {
                            let pos := sub(add(searchPtr, i), subjectData)
                            if lt(pos, subjectLen) {
                                result := pos
                                searchPtr := endPtr
                                break
                            }
                        }
                    }
                }
            }
        }
    }

    /// @notice Unsafely slices a bytes array by modifying the original array.
    /// The integrity of the original array is NOT maintained.
    /// @dev It is assumed that subject.length >= end
    /// @param subject The bytes array to slice
    /// @param start The start index
    /// @param end The end index, not inclusive
    /// @return result The sliced bytes array
    function destructiveSlice(bytes memory subject, uint256 start, uint256 end)
        internal
        pure
        returns (bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := add(subject, start)
            mstore(result, sub(end, start))
        }
    }

    /// @notice Decodes a bytes32 containing 4 base64 characters to uint32
    /// Inspired by https://github.com/Vectorized/solady/blob/b609a9c79ce541c2beca7a7d247665e7c93942a3/src/utils/Base64.sol#L105
    /// @param input bytes32 containing base64 characters
    /// @return result decoded uint32 value (little-endian)
    function decodeBase64Uint32LittleEndian(bytes32 input) internal pure returns (uint32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let fmp := mload(0x40)

            // Load the base64 decode table into scratch space
            let m := 0xfc000000fc00686c7074787c8084888c9094989ca0a4a8acb0b4b8bcc0c4c8cc
            mstore(0x5b, m)
            mstore(0x3b, 0x04080c1014181c2024282c3034383c4044484c5054585c6064)
            mstore(0x1a, 0xf8fcf800fcd0d4d8dce0e4e8ecf0f4)

            // Decode 4 base64 characters to 3 bytes
            let decoded :=
                or(
                    and(m, mload(byte(28, input))),
                    shr(
                        6,
                        or(
                            and(m, mload(byte(29, input))),
                            shr(6, or(and(m, mload(byte(30, input))), shr(6, mload(byte(31, input)))))
                        )
                    )
                )

            // Arrange in little-endian order
            result := or(or(byte(31, decoded), shl(8, byte(30, decoded))), shl(16, byte(29, decoded)))

            // Restore scratch space and FMP
            mstore(0x60, 0)
            mstore(0x40, fmp)
        }
    }
}
