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
    uint32 internal constant DEFAULT_RSA_EXPONENT = 65537;
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
        AzureTDX.AkPub memory akPub = attestationDocument.instanceInfo.extractAkPub();
        tpmQuote.verify(akPub, pcrs, tpmNonce);

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
        // Compiling this with solc 0.8.28, the result is actually very
        // efficient.
        // The difference from encoding it like this versus pre-allocating the
        // string and manipulating the FMP to fill it is about 400 gas only,
        // even if it feels like this would lead to way more gas usage.
        // forgefmt: disable-next-item
        return sha256(bytes(abi.encodePacked(
            "{\"AttestationReport\":\"",
            Base64.encode(instanceInfo.attestationReport),
            "\",\"RuntimeData\":\"",
            Base64.encode(instanceInfo.runtimeData),
            "\"}",
            extraData
        )));
    }
}

/// @title AzureTDXInstanceInfo
/// @notice Instance information implementation for Azure TDX attestation
library AzureTDXInstanceInfo {
    /// @notice Verifies an instance information
    /// @param instanceInfo The instance information to verify
    function verify(AzureTDX.InstanceInfo memory instanceInfo) internal pure {
        _verifyHclReport(instanceInfo);
    }

    /// @notice Extracts the attestation key public key from the attestation report
    /// @param instanceInfo The instance information containing the attestation report
    /// @return akPub The extracted attestation key public key
    function extractAkPub(AzureTDX.InstanceInfo memory instanceInfo)
        internal
        pure
        returns (AzureTDX.AkPub memory akPub)
    {
        return AzureTDXRuntimeData.extractAkPub(instanceInfo.runtimeData);
    }

    /// @notice Validates HCL report JSON and verifies it contains the correct AK public key
    /// @param instanceInfo The instance information containing the runtime data
    function _verifyHclReport(AzureTDX.InstanceInfo memory instanceInfo) private pure {
        // Verify SHA256 hash of runtimeData matches beginning of reportData
        bytes32 runtimeDataHash = sha256(instanceInfo.runtimeData);
        bytes32 reportDataPrefix = _extractReportDataPrefix(instanceInfo.attestationReport);

        if (runtimeDataHash != reportDataPrefix) {
            revert AzureTDXErrors.AttestationReportHashMismatch(runtimeDataHash, reportDataPrefix);
        }
    }

    /// @notice Extracts report data prefix from a TDX quote
    /// @param quote The TDX quote containing the report data hash as a prefix
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
    function _validatePCRs(AzureTDX.TPMQuote memory tpmQuote, AzureTDX.PCR[] memory pcrs) private pure {
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

        if (pcrDigest != sha256(abi.encodePacked(tpmQuote.pcrs))) {
            revert AzureTDXErrors.PCRDigestMismatch(pcrDigest, sha256(abi.encodePacked(tpmQuote.pcrs)));
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
        uint32 exponent = akPub.exponentRaw == 0 ? AzureTDXConstants.DEFAULT_RSA_EXPONENT : akPub.exponentRaw;

        if (!RSA.pkcs1Sha256(message, signature, abi.encodePacked(exponent), akPub.modulusRaw)) {
            revert AzureTDXErrors.InvalidSignature();
        }
    }
}

/// @title AzureTDXRuntimeData
/// @notice Runtime data implementation for Azure TDX attestation
library AzureTDXRuntimeData {
    uint256 internal constant RUNTIME_DATA_START_LEN = 63;
    uint256 internal constant RSA_EXPONENT_B64_OFFSET = 63;
    uint256 internal constant RSA_EXPONENT_B64_LEN = 4;
    uint256 internal constant RSA_MODULUS_SEP_OFFSET = 63 + 5; // len(e) + len("\"")
    uint256 internal constant RSA_MODULUS_SEP_LEN = 6; // ",\"n\":\""
    uint256 internal constant RSA_MODULUS_SEP = 0x2c226e223a22;
    uint256 internal constant RSA_MODULUS_OFFSET = 63 + 5 + 6;
    uint8 internal constant QUOTE = 0x22;

    // keccak256("{\"keys\":[{\"kid\":\"HCLAkPub\",\"key_ops\":[\"sign\"],\"kty\":\"RSA\",\"e\":\"")
    bytes32 internal constant RUNTIME_DATA_START_HASH =
        0xba515574eb2b1bc4cfcbc184a643b480d1da3f86e0518d3eedee7cc814e508cc;

    /// @notice Extracts the attestation key public key from the runtime data
    /// @dev This assumes the JSON format of the runtime data being "keys" as
    /// the first element, then the "HCLAkPub" as its first child, with the
    /// key-values, ordered, being "kid": "HCLAkPub", "key_ops": ["sign"],
    /// "kty": "RSA", "e": <exponentb64>, "n": <modulusb64>.
    /// The exponentb64 is assumed to be 4 characters long.
    /// @param runtimeData The runtime data containing the attestation key public key
    /// @return akPub The extracted attestation key public key
    function extractAkPub(bytes memory runtimeData) internal pure returns (AzureTDX.AkPub memory akPub) {
        if (runtimeData.length < RSA_MODULUS_OFFSET) {
            revert AzureTDXErrors.InvalidRuntimeData();
        }

        bool valid;
        bytes32 exponentB64;

        /// @solidity memory-safe-assembly
        assembly {
            let runtimeDataStart := add(runtimeData, 0x20)

            let runtimeDataHash := keccak256(runtimeDataStart, RUNTIME_DATA_START_LEN)
            valid := eq(runtimeDataHash, RUNTIME_DATA_START_HASH)
            let lookup := mload(add(runtimeDataStart, RUNTIME_DATA_START_LEN))
            if eq(byte(RSA_EXPONENT_B64_LEN, lookup), QUOTE) { exponentB64 := and(lookup, shl(224, 0xffffffff)) }
            valid := and(valid, eq(shr(208, mload(add(runtimeDataStart, RSA_MODULUS_SEP_OFFSET))), RSA_MODULUS_SEP))
        }

        if (!valid || exponentB64 == bytes32(0)) {
            revert AzureTDXErrors.InvalidRuntimeData();
        }

        uint256 nEnd = SoladyFuture.indexOfByte(runtimeData, bytes1(QUOTE), RSA_MODULUS_OFFSET);

        if (nEnd == type(uint256).max) {
            revert AzureTDXErrors.InvalidRuntimeData();
        }

        // if the exponent is "AQAB" (0x41514142), it is 0
        if (exponentB64 == bytes32(bytes4("AQAB"))) {
            akPub.exponentRaw = 0;
        } else {
            akPub.exponentRaw = Base64Ext.decodeBase64Uint24LittleEndian(exponentB64);
        }

        akPub.modulusRaw = Base64Ext.decode(runtimeData, RSA_MODULUS_OFFSET, nEnd);

        return akPub;
    }
}

/// @title Base64Ext
/// @notice Extension of Base64
library Base64Ext {
    /// @notice Decodes a base64 string
    /// @dev We use a destructive slice to create a new string, then decode it
    /// and later on restore the original string.
    /// @param base64 The base64 string to decode
    /// @param offset The offset to start decoding from
    /// @param end The end of the string to decode
    /// @return decoded The decoded string
    function decode(bytes memory base64, uint256 offset, uint256 end) internal pure returns (bytes memory) {
        string memory ptr;

        // Destructive slice to create a new string, store the original slot
        // value in tmp
        uint256 tmp;
        /// @solidity memory-safe-assembly
        assembly {
            ptr := add(base64, offset)
            tmp := mload(ptr)
            mstore(ptr, sub(end, offset))
        }

        bytes memory decoded = Base64.decode(ptr);

        // Restore the original string slot value
        /// @solidity memory-safe-assembly
        assembly {
            mstore(ptr, tmp)
        }

        return decoded;
    }

    /// @notice Decodes a bytes32 containing 4 base64 characters to uint32
    /// Inspired by https://github.com/Vectorized/solady/blob/b609a9c79ce541c2beca7a7d247665e7c93942a3/src/utils/Base64.sol#L105
    /// @param input bytes32 containing base64 characters
    /// @return result decoded uint32 value (little-endian)
    function decodeBase64Uint24LittleEndian(bytes32 input) internal pure returns (uint24 result) {
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

/// @title SoladyFuture
/// @notice Methods that are not available in solady yet
library SoladyFuture {
    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from left to right, starting from `from`. Optimized for byte needles.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    /// Included after https://github.com/Vectorized/solady/pull/1425 and
    /// https://github.com/Vectorized/solady/pull/1427
    function indexOfByte(bytes memory subject, bytes1 needle, uint256 from) internal pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := not(0) // Initialize to `NOT_FOUND`.
            if gt(mload(subject), from) {
                let start := add(subject, 0x20)
                let end := add(start, mload(subject))
                let m := div(not(0), 255) // `0x0101 ... `.
                let h := mul(byte(0, needle), m) // Replicating needle mask.
                m := not(shl(7, m)) // `0x7f7f ... `.
                for { let i := add(start, from) } 1 {} {
                    let c := xor(mload(i), h) // Load 32-byte chunk and xor with mask.
                    c := not(or(or(add(and(c, m), m), c), m)) // Each needle byte will be `0x80`.
                    if c {
                        c := and(not(shr(shl(3, sub(end, i)), not(0))), c) // Truncate bytes past the end.
                        if c {
                            let r := shl(7, lt(0x8421084210842108cc6318c6db6d54be, c)) // Save bytecode.
                            r := or(shl(6, lt(0xffffffffffffffff, shr(r, c))), r)
                            // forgefmt: disable-next-item
                            result := add(sub(i, start), shr(3, xor(byte(and(0x1f, shr(byte(24,
                                mul(0x02040810204081, shr(r, c))), 0x8421084210842108cc6318c6db6d54be)),
                                0xc0c8c8d0c8e8d0d8c8e8e0e8d0d8e0f0c8d0e8d0e0e0d8f0d0d0e0d8f8f8f8f8), r)))
                            break
                        }
                    }
                    i := add(i, 0x20)
                    if iszero(lt(i, end)) { break }
                }
            }
        }
    }
}
