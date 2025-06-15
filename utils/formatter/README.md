# Formatter

This formatter converts Constellation-issued Azure TDX attestation quotes into a format suitable for the on-chain verifier. It extracts and restructures TPM attestation data, instance information, and cryptographic signatures.

## Usage

```bash
go run main.go <input_file>
```

Example:
```bash
go run main.go samples/example.json
```

## Input Format

The formatter expects a JSON file with the following structure:
- `rawQuote`: Constellation attestation document containing TPM quote and instance info
- `nonce`: Hex-encoded nonce value (with or without "0x" prefix)

See [`samples/example.json`](./samples/example.json) for a complete example.

## Output Format

The formatter produces JSON output containing:
- Decoded TPM quote data (quote bytes, RSA signature, PCR values)
- Instance information (attestation report, runtime data)
- User data
- Extracted attestation key public key components
- Computed runtime data hash

This output format is directly suitable for the on-chain verifier.
