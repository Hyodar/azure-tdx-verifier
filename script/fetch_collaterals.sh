#!/bin/bash

set -e

FMSPC="00806F050000"

TCB_FILE="tcb.json"
QE_IDENTITY_FILE="qe_identity.json"
TCB_SIGNING_CERT_FILE="tcb_signing_cert.pem"
TCB_SIGNING_DER_FILE="tcb_signing_cert.der"
TCB_SIGNING_HEX_FILE="tcb_signing_cert.hex"

# Fetch TCB info and capture headers
echo "Fetching TCB info..."
RESPONSE=$(curl -s -D - -X GET "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=${FMSPC}")

# Extract the body (JSON) and save it
echo "$RESPONSE" | sed '1,/^\r$/d' > ${TCB_FILE}

# Extract the Tcb-Info-Issuer-Chain header
TCB_CERT_CHAIN=$(echo "$RESPONSE" | grep -i "^Tcb-Info-Issuer-Chain:" | cut -d' ' -f2- | tr -d '\r\n')

if [ -z "$TCB_CERT_CHAIN" ]; then
    echo "Error: Could not find Tcb-Info-Issuer-Chain header"
    exit 1
fi

echo "Found Tcb-Info-Issuer-Chain header"

# URL decode the certificate chain
# Using printf to decode URL encoding
url_decode() {
    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

DECODED_CERT=$(url_decode "$TCB_CERT_CHAIN")

# Extract only the first certificate from the chain, which is the TCB signing
# certificate
FIRST_CERT=$(echo "$DECODED_CERT" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | sed -n '1,/-----END CERTIFICATE-----/p')

# Save the signing certificate to PEM file
echo "$FIRST_CERT" > ${TCB_SIGNING_CERT_FILE}
echo "Saved signing certificate to ${TCB_SIGNING_CERT_FILE}"

# Convert PEM to DER format
openssl x509 -in ${TCB_SIGNING_CERT_FILE} -outform DER -out ${TCB_SIGNING_DER_FILE}
echo "Converted to DER format: ${TCB_SIGNING_DER_FILE}"

# Convert DER to hex dump
xxd -p -c 1000000 ${TCB_SIGNING_DER_FILE} > ${TCB_SIGNING_HEX_FILE}
echo "Created hex dump: ${TCB_SIGNING_HEX_FILE}"

# Also display the hex dump
echo -e "\nHex dump of DER certificate:"
xxd ${TCB_SIGNING_DER_FILE} | head -20
echo "..."

# Fetch QE identity
echo -e "\nFetching QE identity..."
curl -s -X GET "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity" > ${QE_IDENTITY_FILE}

# Process TCB JSON (lowercase fmspc)
jq '.tcbInfo.fmspc |= ascii_downcase' ${TCB_FILE} > temp.json && mv temp.json ${TCB_FILE}
echo "Processed TCB JSON file"

# Display certificate info
echo -e "\nCertificate information:"
openssl x509 -in ${TCB_SIGNING_CERT_FILE} -noout -subject -issuer -dates

echo -e "\nAll files created successfully:"
ls -la ${TCB_FILE} ${QE_IDENTITY_FILE} ${TCB_SIGNING_CERT_FILE} ${TCB_SIGNING_DER_FILE} ${TCB_SIGNING_HEX_FILE}
