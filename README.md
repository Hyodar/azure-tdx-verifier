# Azure TDX Verifier

Solidity library for verifying Azure MAA TDX Attestations.

Currently based on the [Constellation](https://github.com/edgelesssys/constellation)
standard for attestation issuance and verification.

## Installation

```bash
forge install Hyodar/azure-tdx-verifier
```

## Input formatting

To format the Constellation raw quote input for the TDX verifier, you can
check out the CLI utility in [`utils/formatter`](utils/formatter).
