package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	decodedHclAkPub, err := tpm2.DecodePublic(doc.Attestation.AkPub)
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

	userData, err := base64.StdEncoding.DecodeString(doc.UserData)
	if err != nil {
		panic(err)
	}

	nonce, err := hex.DecodeString(strings.TrimPrefix(inputData.Nonce, "0x"))
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
	output.AttestationDocument.UserData = HexBytes(userData)
	output.Pcrs = trustedPcrs
	output.Nonce = HexBytes(nonce)
	output.AdditionalData.HclAkPub.ExponentRaw = decodedHclAkPub.RSAParameters.ExponentRaw
	output.AdditionalData.HclAkPub.ModulusRaw = HexBytes(decodedHclAkPub.RSAParameters.ModulusRaw)
	output.AdditionalData.RuntimeDataHash = HexBytes32(runtimeDataHash)

	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(jsonOutput))
}
