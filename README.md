# Azure TDX Verifier

[![Build][build-shield]][build-url]
[![Solidity][solidity-shield]][solidity-url]
[![License][license-shield]][license-url]

A gas-optimized Solidity library for on-chain verification of Azure vTPM TDX attestations based on the [Constellation](https://github.com/edgelesssys/constellation) format. This library enables smart contracts to verify the authenticity and integrity of Azure confidential computing environments.

This library does not verify the TDX quote. It only verifies the TPM quote and the attestation document. The verification of the TDX quote can be done through, e.g. the [Automata DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation) contracts.

## Overview

Azure TDX Verifier provides a trustless way to verify Azure TDX attestations on-chain. It validates TPM quotes, extracts attestation keys from runtime data, and prepares TDX quotes for further verification. The library is designed to be compatible with the [Constellation](https://github.com/edgelesssys/constellation) attestation issuance format.

## Installation

```bash
forge install
```

## Usage

### Basic Verification

```solidity
import {AzureTDX} from "azure-tdx-verifier/src/AzureTDX.sol";

contract AzureTDXVerifier {
    function verifyAttestation(AzureTDX.VerifyParams memory params) external view {
        bytes memory tdxQuote = AzureTDX.verify(params);

        _invalidateNonce(params.nonce);
        _verifyTDXQuote(tdxQuote);
    }

    function _verifyTDXQuote(bytes memory tdxQuote) internal view {
        // Verify the TDX quote using an external TDX verification service
    }

    function _invalidateNonce(bytes memory nonce) internal view {
        // Invalidate the nonce if needed
    }
}
```

## Utilities

### Formatter

Converts Constellation-issued quotes to the verifier input format.

```bash
go run utils/formatter/main.go input.json > output.json
```

### Collateral Fetcher

Downloads Intel SGX/TDX collaterals for a specific FMSPC and converts it to the expected format for the [Automata On Chain PCCS](https://github.com/automata-network/automata-on-chain-pccs). Includes the TCB info, QE identity, and signing certificate.

```bash
./script/fetch_collaterals.sh
```

## Testing

Run the test suite:

```bash
forge test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

[solidity-shield]: https://img.shields.io/badge/solidity-%5E0.8.0-aa6746
[solidity-url]: https://docs.soliditylang.org/

[build-shield]: https://img.shields.io/github/actions/workflow/status/Hyodar/azure-tdx-verifier/build.yml?branch=master&label=build
[build-url]: https://github.com/Hyodar/azure-tdx-verifier/actions/workflows/build.yml

[license-shield]: https://img.shields.io/badge/License-MIT-lightgray.svg
[license-url]: https://opensource.org/licenses/MIT
