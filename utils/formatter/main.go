package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

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
	Nonce    string          `json:"nonce"`
}

type InstanceInfo struct {
	AttestationReport string `json:"attestationReport"`
	RuntimeData       string `json:"runtimeData"`
}

type AttestationDocument struct {
	Attestation  *attest.Attestation
	InstanceInfo []byte
	UserData     string
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
		UserData HexBytes `json:"userData"`
	} `json:"attestationDocument"`
	Pcrs []struct {
		Index uint8      `json:"index"`
		Value HexBytes32 `json:"value"`
	} `json:"pcrs"`
	Nonce          HexBytes `json:"nonce"`
	AdditionalData struct {
		HclAkPub struct {
			ExponentRaw uint32   `json:"exponentRaw"`
			ModulusRaw  HexBytes `json:"modulusRaw"`
		} `json:"hclAkPub"`
		RuntimeDataHash HexBytes32 `json:"runtimeDataHash"`
	} `json:"additionalData"`
}

func main() {
	log.SetPrefix("[formatter] ")
	log.SetFlags(0)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input_file>\n", os.Args[0])
		os.Exit(1)
	}

	inputFilename := os.Args[1]
	log.Printf("Processing input file: %s", inputFilename)

	input, err := os.ReadFile(inputFilename)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	var inputData InputData
	if err := json.Unmarshal(input, &inputData); err != nil {
		log.Fatalf("Failed to parse input JSON: %v", err)
	}
	log.Println("Successfully parsed input data")

	var doc AttestationDocument
	if err := json.Unmarshal(inputData.RawQuote, &doc); err != nil {
		log.Fatalf("Failed to parse attestation document from rawQuote: %v", err)
	}
	log.Println("Successfully parsed attestation document")

	var instanceInfo InstanceInfo
	if err := json.Unmarshal(doc.InstanceInfo, &instanceInfo); err != nil {
		log.Fatalf("Failed to parse instance info: %v", err)
	}
	log.Println("Successfully parsed instance info")

	decodedHclAkPub, err := tpm2.DecodePublic(doc.Attestation.AkPub)
	if err != nil {
		log.Fatalf("Failed to decode HCL attestation key public key: %v", err)
	}
	log.Println("Successfully decoded HCL attestation key")

	var sha256Quote *tpmproto.Quote
	for _, quote := range doc.Attestation.Quotes {
		if quote.Pcrs.Hash == tpmproto.HashAlgo_SHA256 {
			sha256Quote = quote
			break
		}
	}
	if sha256Quote == nil {
		log.Fatalf("No SHA256 quote found in attestation quotes")
	}
	log.Println("Found SHA256 quote")

	pcrs := [24]HexBytes32{}
	for i, pcr := range sha256Quote.Pcrs.Pcrs {
		copy(pcrs[i][:], pcr[:])
	}

	decodedSig, err := tpm2.DecodeSignature(bytes.NewBuffer(sha256Quote.RawSig))
	if err != nil {
		log.Fatalf("Failed to decode TPM signature: %v", err)
	}
	log.Println("Successfully decoded TPM signature")

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
		log.Fatalf("Failed to decode attestation report: %v", err)
	}
	log.Printf("Decoded attestation report (%d bytes)", len(attestationReport))

	runtimeData, err := base64.StdEncoding.DecodeString(instanceInfo.RuntimeData)
	if err != nil {
		log.Fatalf("Failed to decode runtime data: %v", err)
	}
	log.Printf("Decoded runtime data (%d bytes)", len(runtimeData))

	userData, err := base64.StdEncoding.DecodeString(doc.UserData)
	if err != nil {
		log.Fatalf("Failed to decode user data: %v", err)
	}
	log.Printf("Decoded user data (%d bytes)", len(userData))

	nonce, err := hex.DecodeString(strings.TrimPrefix(inputData.Nonce, "0x"))
	if err != nil {
		log.Fatalf("Failed to decode nonce from hex: %v", err)
	}
	log.Printf("Decoded nonce (%d bytes)", len(nonce))

	runtimeDataHash := sha256.Sum256(runtimeData)

	output := OutputData{}

	output.AttestationDocument.Attestation.TpmQuote.Quote = HexBytes(sha256Quote.Quote)
	output.AttestationDocument.Attestation.TpmQuote.RsaSignature = HexBytes(decodedSig.RSA.Signature)
	output.AttestationDocument.Attestation.TpmQuote.Pcrs = pcrs
	output.AttestationDocument.InstanceInfo.AttestationReport = HexBytes(attestationReport)
	output.AttestationDocument.InstanceInfo.RuntimeData = HexBytes(runtimeData)
	output.AttestationDocument.UserData = HexBytes(userData)
	output.Pcrs = trustedPcrs
	output.Nonce = HexBytes(nonce)
	output.AdditionalData.HclAkPub.ExponentRaw = decodedHclAkPub.RSAParameters.ExponentRaw
	output.AdditionalData.HclAkPub.ModulusRaw = HexBytes(decodedHclAkPub.RSAParameters.ModulusRaw)
	output.AdditionalData.RuntimeDataHash = HexBytes32(runtimeDataHash)

	log.Println("Formatting output data...")
	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal output JSON: %v", err)
	}

	log.Println("Successfully formatted attestation data")
	fmt.Println(string(jsonOutput))
}
