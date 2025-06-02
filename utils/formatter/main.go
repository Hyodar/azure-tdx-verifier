package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/proto/attest"
	tpmproto "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}
	*h = decoded
	return nil
}

type HexBytes32 [32]byte

func (h HexBytes32) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%064x", h))
}

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

type OutputData struct {
	AttestationDocument struct {
		Attestation struct {
			TpmQuote struct {
				Quote        HexBytes       `json:"quote"`
				RsaSignature HexBytes       `json:"rsaSignature"`
				Pcrs         [24]HexBytes32 `json:"pcrs"`
			} `json:"tpmQuote"`
		} `json:"attestation"`
		InstanceInfo struct {
			AttestationReport HexBytes `json:"attestationReport"`
			RuntimeData       HexBytes `json:"runtimeData"`
		} `json:"instanceInfo"`
		UserData string `json:"userData"`
	} `json:"attestationDocument"`
	TrustedInput struct {
		AkPub struct {
			ExponentRaw uint32   `json:"exponentRaw"`
			ModulusRaw  HexBytes `json:"modulusRaw"`
		} `json:"akPub"`
		RuntimeDataHash HexBytes32 `json:"runtimeDataHash"`
		Pcrs            []struct {
			Index uint8      `json:"index"`
			Value HexBytes32 `json:"value"`
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

	pcrs := [24]HexBytes32{}
	for i, pcr := range sha256Quote.Pcrs.Pcrs {
		copy(pcrs[i][:], pcr[:])
	}

	decodedSig, err := tpm2.DecodeSignature(bytes.NewBuffer(sha256Quote.RawSig))
	if err != nil {
		panic(err)
	}

	trustedPcrs := []struct {
		Index uint8      `json:"index"`
		Value HexBytes32 `json:"value"`
	}{}

	for i, pcr := range pcrs {
		val := HexBytes32{}
		copy(val[:], pcr[:])

		trustedPcrs = append(trustedPcrs, struct {
			Index uint8      `json:"index"`
			Value HexBytes32 `json:"value"`
		}{
			Index: uint8(i),
			Value: val,
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

	runtimeDataHash := sha256.Sum256(runtimeData)

	output := OutputData{}

	output.AttestationDocument.Attestation.TpmQuote.Quote = HexBytes(sha256Quote.Quote)
	output.AttestationDocument.Attestation.TpmQuote.RsaSignature = HexBytes(decodedSig.RSA.Signature)
	output.AttestationDocument.Attestation.TpmQuote.Pcrs = pcrs
	output.AttestationDocument.InstanceInfo.AttestationReport = HexBytes(attestationReport)
	output.AttestationDocument.InstanceInfo.RuntimeData = HexBytes(runtimeData)
	output.AttestationDocument.UserData = inputData.UserData
	output.TrustedInput.AkPub.ExponentRaw = decodedAkPub.RSAParameters.ExponentRaw
	output.TrustedInput.AkPub.ModulusRaw = HexBytes(decodedAkPub.RSAParameters.ModulusRaw)
	output.TrustedInput.RuntimeDataHash = HexBytes32(runtimeDataHash)
	output.TrustedInput.Pcrs = trustedPcrs
	output.Nonce = inputData.Nonce

	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(jsonOutput))
}
