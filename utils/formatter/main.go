package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/google/go-tpm-tools/proto/attest"
	tpmproto "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

type InputData struct {
	RawQuote json.RawMessage `json:"rawQuote"`
	UserData string          `json:"userData"`
	Nonce    string          `json:"nonce"`
}

type InstanceInfo struct {
	AttestationReport string `json:"attestationReport"`
	RuntimeData       string `json:"runtimeData"`
}

type AttestationDocument struct {
	Attestation  *attest.Attestation
	InstanceInfo []byte
	UserData     []byte
}

type AttestationOutput struct {
	AttestationDocument struct {
		Attestation struct {
			TpmQuote struct {
				Quote        string   `json:"quote"`
				RsaSignature string   `json:"rsaSignature"`
				Pcrs         []string `json:"pcrs"` // PCR values as big integer strings
				PcrsBitMap   uint32   `json:"pcrsBitMap"`
			} `json:"tpmQuote"`
		} `json:"attestation"`
		InstanceInfo struct {
			AttestationReport string `json:"attestationReport"`
			RuntimeData       string `json:"runtimeData"`
		} `json:"instanceInfo"`
		UserData string `json:"userData"`
	} `json:"attestationDocument"`
	TrustedInput struct {
		AkPub struct {
			ExponentRaw uint32 `json:"exponentRaw"`
			ModulusRaw  string `json:"modulusRaw"`
		} `json:"akPub"`
		RuntimeDataHash string `json:"runtimeDataHash"`
		Pcrs            []struct {
			Index uint8  `json:"index"`
			Value string `json:"value"` // PCR value as big integer string
		} `json:"pcrs"`
	} `json:"trustedInput"`
	Nonce string `json:"nonce"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("No file provided")
		os.Exit(1)
	}

	inputFilename := os.Args[1]

	input, err := os.ReadFile(inputFilename)
	if err != nil {
		panic(err)
	}

	var inputData InputData
	if err := json.Unmarshal(input, &inputData); err != nil {
		panic(err)
	}

	var doc AttestationDocument
	if err := json.Unmarshal(inputData.RawQuote, &doc); err != nil {
		panic(err)
	}

	var instanceInfo InstanceInfo
	if err := json.Unmarshal(doc.InstanceInfo, &instanceInfo); err != nil {
		panic(err)
	}

	decodedAkPub, err := tpm2.DecodePublic(doc.Attestation.AkPub)
	if err != nil {
		panic(err)
	}

	var sha256Quote *tpmproto.Quote
	for _, quote := range doc.Attestation.Quotes {
		if quote.Pcrs.Hash == tpmproto.HashAlgo_SHA256 {
			sha256Quote = quote
			break
		}
	}
	if sha256Quote == nil {
		panic("no SHA256 quote found")
	}

	pcrs := [24][32]byte{}
	for i, pcr := range sha256Quote.Pcrs.Pcrs {
		copy(pcrs[i][:], pcr[:])
	}

	pcrBigIntStrs := []string{}
	for _, pcr := range pcrs {
		bigInt := new(big.Int).SetBytes(pcr[:])
		pcrBigIntStrs = append(pcrBigIntStrs, fmt.Sprintf("0x%064x", bigInt))
	}

	decodedSig, err := tpm2.DecodeSignature(bytes.NewBuffer(sha256Quote.RawSig))
	if err != nil {
		panic(err)
	}

	trustedPcrs := []struct {
		Index uint8  `json:"index"`
		Value string `json:"value"`
	}{}

	for i, pcr := range pcrs {
		bigInt := new(big.Int).SetBytes(pcr[:])
		trustedPcrs = append(trustedPcrs, struct {
			Index uint8  `json:"index"`
			Value string `json:"value"`
		}{
			Index: uint8(i),
			Value: fmt.Sprintf("0x%064x", bigInt),
		})
	}

	attestationReport, err := base64.StdEncoding.DecodeString(instanceInfo.AttestationReport)
	if err != nil {
		panic(err)
	}

	runtimeData, err := base64.StdEncoding.DecodeString(instanceInfo.RuntimeData)
	if err != nil {
		panic(err)
	}

	output := AttestationOutput{}

	output.AttestationDocument.Attestation.TpmQuote.Quote = hex.EncodeToString(sha256Quote.Quote)
	output.AttestationDocument.Attestation.TpmQuote.RsaSignature = hex.EncodeToString(decodedSig.RSA.Signature)
	output.AttestationDocument.Attestation.TpmQuote.Pcrs = pcrBigIntStrs

	output.AttestationDocument.InstanceInfo.AttestationReport = hex.EncodeToString(attestationReport)
	output.AttestationDocument.InstanceInfo.RuntimeData = hex.EncodeToString(runtimeData)
	output.AttestationDocument.UserData = inputData.UserData

	output.TrustedInput.AkPub.ExponentRaw = decodedAkPub.RSAParameters.ExponentRaw
	output.TrustedInput.AkPub.ModulusRaw = hex.EncodeToString(decodedAkPub.RSAParameters.ModulusRaw)
	output.TrustedInput.RuntimeDataHash = hex.EncodeToString(sha256Hash(runtimeData))
	output.TrustedInput.Pcrs = trustedPcrs

	output.Nonce = inputData.Nonce

	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(jsonOutput))
}

// Helper function to calculate SHA256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
