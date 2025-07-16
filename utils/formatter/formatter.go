package formatter

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/google/go-tpm-tools/proto/attest"
	tpmproto "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	TPMPCRCount = 24
	HexPrefix   = "0x"
)

type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(HexPrefix + hex.EncodeToString(h))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return fmt.Errorf("unmarshal hex string: %w", err)
	}

	hexStr = strings.TrimPrefix(hexStr, HexPrefix)

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("decode hex string: %w", err)
	}

	*h = decoded
	return nil
}

type HexBytes32 [32]byte

func (h HexBytes32) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%s%064x", HexPrefix, h))
}

type InputData struct {
	RawQuote json.RawMessage `json:"rawQuote"`
	Nonce    HexBytes        `json:"nonce"`
}

func (i *InputData) Validate() error {
	if len(i.RawQuote) == 0 {
		return fmt.Errorf("rawQuote is empty")
	}
	return nil
}

type InstanceInfo struct {
	AttestationReport string `json:"attestationReport"`
	RuntimeData       string `json:"runtimeData"`
}

func (i *InstanceInfo) DecodeAttestationReport() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(i.AttestationReport)
	if err != nil {
		return nil, fmt.Errorf("decode attestation report: %w", err)
	}
	return data, nil
}

func (i *InstanceInfo) DecodeRuntimeData() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(i.RuntimeData)
	if err != nil {
		return nil, fmt.Errorf("decode runtime data: %w", err)
	}
	return data, nil
}

type AttestationDocument struct {
	Attestation  *attest.Attestation
	InstanceInfo []byte
	UserData     string
}

func (a *AttestationDocument) DecodeUserData() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(a.UserData)
	if err != nil {
		return nil, fmt.Errorf("decode user data: %w", err)
	}
	return data, nil
}

type PCRValue struct {
	Index uint8      `json:"index"`
	Value HexBytes32 `json:"value"`
}

type TPMQuoteData struct {
	Quote        HexBytes                `json:"quote"`
	RsaSignature HexBytes                `json:"rsaSignature"`
	Pcrs         [TPMPCRCount]HexBytes32 `json:"pcrs"`
}

type RuntimeDataInfo struct {
	Raw      HexBytes `json:"raw"`
	HclAkPub struct {
		ExponentRaw uint32   `json:"exponentRaw"`
		ModulusRaw  HexBytes `json:"modulusRaw"`
	} `json:"hclAkPub"`
}

type OutputData struct {
	AttestationDocument struct {
		Attestation struct {
			TpmQuote TPMQuoteData `json:"tpmQuote"`
		} `json:"attestation"`
		InstanceInfo struct {
			AttestationReport HexBytes        `json:"attestationReport"`
			RuntimeData       RuntimeDataInfo `json:"runtimeData"`
		} `json:"instanceInfo"`
		UserData HexBytes `json:"userData"`
	} `json:"attestationDocument"`
	Pcrs           []PCRValue `json:"pcrs"`
	Nonce          HexBytes   `json:"nonce"`
	AdditionalData struct {
		RuntimeDataHash HexBytes32 `json:"runtimeDataHash"`
	} `json:"additionalData"`
}

type AzureTDXFormatter struct {
	logger *slog.Logger
}

// NewAzureTDXFormatter creates a new instance of AzureTDXFormatter with a default logger
// that discards all output. Use NewAzureTDXFormatterWithLogger to provide a custom logger.
func NewAzureTDXFormatter() *AzureTDXFormatter {
	return &AzureTDXFormatter{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// NewAzureTDXFormatterWithLogger creates a new instance with a custom logger
// Example:
//
//	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
//	formatter := NewAzureTDXFormatterWithLogger(logger)
func NewAzureTDXFormatterWithLogger(logger *slog.Logger) *AzureTDXFormatter {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &AzureTDXFormatter{
		logger: logger,
	}
}

// SetLogger sets a custom logger for the formatter
func (f *AzureTDXFormatter) SetLogger(logger *slog.Logger) {
	if logger != nil {
		f.logger = logger
	}
}

// FormatReader reads and formats an attestation document from an io.Reader
func (f *AzureTDXFormatter) FormatReader(reader io.Reader) (*OutputData, error) {
	if reader == nil {
		return nil, fmt.Errorf("reader is nil")
	}

	f.logger.Debug("reading attestation data from reader")
	input, err := io.ReadAll(reader)
	if err != nil {
		f.logger.Error("failed to read input", "error", err)
		return nil, fmt.Errorf("read input: %w", err)
	}
	f.logger.Debug("read input data", "size", len(input))

	var inputData InputData
	if err := json.Unmarshal(input, &inputData); err != nil {
		f.logger.Error("failed to parse input JSON", "error", err)
		return nil, fmt.Errorf("parse input JSON: %w", err)
	}

	f.logger.Info("successfully parsed input data")
	return f.Format(&inputData)
}

// FormatFile reads and formats an attestation document from a file
// This is a convenience wrapper around FormatReader
func (f *AzureTDXFormatter) FormatFile(inputFilename string) (*OutputData, error) {
	if inputFilename == "" {
		return nil, fmt.Errorf("input filename is empty")
	}

	file, err := os.Open(inputFilename)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer file.Close()

	return f.FormatReader(file)
}

// Format processes the attestation input data and returns formatted output
func (f *AzureTDXFormatter) Format(inputData *InputData) (*OutputData, error) {
	if inputData == nil {
		return nil, fmt.Errorf("input data is nil")
	}

	f.logger.Info("starting attestation format process")

	if err := inputData.Validate(); err != nil {
		f.logger.Error("input validation failed", "error", err)
		return nil, fmt.Errorf("validate input: %w", err)
	}

	doc, err := f.parseAttestationDocument(inputData.RawQuote)
	if err != nil {
		return nil, err
	}

	instanceInfo, err := f.parseInstanceInfo(doc.InstanceInfo)
	if err != nil {
		return nil, err
	}

	processedData, err := f.processAttestationData(doc, instanceInfo)
	if err != nil {
		return nil, err
	}

	decodedData, err := f.decodeAdditionalData(inputData, doc, instanceInfo)
	if err != nil {
		return nil, err
	}

	output := f.buildOutput(inputData, processedData, decodedData)
	f.logger.Info("attestation format completed successfully")
	return output, nil
}

// parseAttestationDocument parses the raw attestation document
func (f *AzureTDXFormatter) parseAttestationDocument(rawQuote json.RawMessage) (*AttestationDocument, error) {
	var doc AttestationDocument
	if err := json.Unmarshal(rawQuote, &doc); err != nil {
		return nil, fmt.Errorf("parse attestation document: %w", err)
	}

	if doc.Attestation == nil {
		return nil, fmt.Errorf("attestation is nil")
	}

	return &doc, nil
}

// parseInstanceInfo parses the instance information from raw bytes
func (f *AzureTDXFormatter) parseInstanceInfo(rawInstanceInfo []byte) (*InstanceInfo, error) {
	var instanceInfo InstanceInfo
	if err := json.Unmarshal(rawInstanceInfo, &instanceInfo); err != nil {
		return nil, fmt.Errorf("parse instance info: %w", err)
	}
	return &instanceInfo, nil
}

// processedAttestationData holds the processed attestation information
type processedAttestationData struct {
	hclAkPub    *tpm2.Public
	sha256Quote *tpmproto.Quote
	pcrs        [TPMPCRCount]HexBytes32
	decodedSig  *tpm2.Signature
}

// processAttestationData processes the attestation data from the document
func (f *AzureTDXFormatter) processAttestationData(doc *AttestationDocument, instanceInfo *InstanceInfo) (*processedAttestationData, error) {
	f.logger.Debug("decoding HCL attestation key")
	hclAkPub, err := tpm2.DecodePublic(doc.Attestation.AkPub)
	if err != nil {
		f.logger.Error("failed to decode HCL attestation key", "error", err)
		return nil, fmt.Errorf("decode HCL attestation key: %w", err)
	}

	f.logger.Debug("searching for SHA256 quote")
	sha256Quote := f.findSHA256Quote(doc.Attestation.Quotes)
	if sha256Quote == nil {
		f.logger.Error("no SHA256 quote found")
		return nil, fmt.Errorf("no SHA256 quote found")
	}
	f.logger.Debug("found SHA256 quote")

	pcrs, err := f.extractPCRs(sha256Quote)
	if err != nil {
		return nil, err
	}
	f.logger.Debug("extracted PCR values", "count", TPMPCRCount)

	f.logger.Debug("decoding TPM signature")
	decodedSig, err := tpm2.DecodeSignature(bytes.NewBuffer(sha256Quote.RawSig))
	if err != nil {
		f.logger.Error("failed to decode TPM signature", "error", err)
		return nil, fmt.Errorf("decode TPM signature: %w", err)
	}

	f.logger.Info("successfully processed attestation data")
	return &processedAttestationData{
		hclAkPub:    &hclAkPub,
		sha256Quote: sha256Quote,
		pcrs:        pcrs,
		decodedSig:  decodedSig,
	}, nil
}

// findSHA256Quote finds the SHA256 quote from the list of quotes
func (f *AzureTDXFormatter) findSHA256Quote(quotes []*tpmproto.Quote) *tpmproto.Quote {
	for _, quote := range quotes {
		if quote != nil && quote.Pcrs != nil && quote.Pcrs.Hash == tpmproto.HashAlgo_SHA256 {
			return quote
		}
	}
	return nil
}

// extractPCRs extracts PCR values from the quote
func (f *AzureTDXFormatter) extractPCRs(quote *tpmproto.Quote) ([TPMPCRCount]HexBytes32, error) {
	var pcrs [TPMPCRCount]HexBytes32

	if quote.Pcrs == nil || quote.Pcrs.Pcrs == nil {
		return pcrs, fmt.Errorf("PCRs not found in quote")
	}

	for i, pcr := range quote.Pcrs.Pcrs {
		if i >= TPMPCRCount {
			break
		}
		copy(pcrs[i][:], pcr[:])
	}

	return pcrs, nil
}

// decodedAdditionalData holds decoded additional data
type decodedAdditionalData struct {
	attestationReport []byte
	runtimeData       []byte
	userData          []byte
	runtimeDataHash   [32]byte
}

// decodeAdditionalData decodes various base64-encoded data fields
func (f *AzureTDXFormatter) decodeAdditionalData(inputData *InputData, doc *AttestationDocument, instanceInfo *InstanceInfo) (*decodedAdditionalData, error) {
	f.logger.Debug("decoding additional data fields")

	attestationReport, err := instanceInfo.DecodeAttestationReport()
	if err != nil {
		return nil, err
	}
	f.logger.Debug("decoded attestation report", "size", len(attestationReport))

	runtimeData, err := instanceInfo.DecodeRuntimeData()
	if err != nil {
		return nil, err
	}
	f.logger.Debug("decoded runtime data", "size", len(runtimeData))

	userData, err := doc.DecodeUserData()
	if err != nil {
		return nil, err
	}
	f.logger.Debug("decoded user data", "size", len(userData))

	runtimeDataHash := sha256.Sum256(runtimeData)
	f.logger.Debug("computed runtime data hash", "hash", hex.EncodeToString(runtimeDataHash[:]))

	return &decodedAdditionalData{
		attestationReport: attestationReport,
		runtimeData:       runtimeData,
		userData:          userData,
		runtimeDataHash:   runtimeDataHash,
	}, nil
}

// buildOutput constructs the final output data structure
func (f *AzureTDXFormatter) buildOutput(inputData *InputData, processed *processedAttestationData, decoded *decodedAdditionalData) *OutputData {
	output := &OutputData{}

	output.AttestationDocument.Attestation.TpmQuote.Quote = HexBytes(processed.sha256Quote.Quote)
	output.AttestationDocument.Attestation.TpmQuote.RsaSignature = HexBytes(processed.decodedSig.RSA.Signature)
	output.AttestationDocument.Attestation.TpmQuote.Pcrs = processed.pcrs

	output.AttestationDocument.InstanceInfo.AttestationReport = HexBytes(decoded.attestationReport)
	output.AttestationDocument.InstanceInfo.RuntimeData.Raw = HexBytes(decoded.runtimeData)
	output.AttestationDocument.InstanceInfo.RuntimeData.HclAkPub.ExponentRaw = processed.hclAkPub.RSAParameters.ExponentRaw
	output.AttestationDocument.InstanceInfo.RuntimeData.HclAkPub.ModulusRaw = HexBytes(processed.hclAkPub.RSAParameters.ModulusRaw)

	output.AttestationDocument.UserData = HexBytes(decoded.userData)

	output.Pcrs = f.buildPCRList(processed.pcrs)

	output.Nonce = inputData.Nonce
	output.AdditionalData.RuntimeDataHash = HexBytes32(decoded.runtimeDataHash)

	return output
}

// buildPCRList creates a list of PCR values with their indices
func (f *AzureTDXFormatter) buildPCRList(pcrs [TPMPCRCount]HexBytes32) []PCRValue {
	pcrList := make([]PCRValue, 0, TPMPCRCount)

	for i, pcr := range pcrs {
		pcrList = append(pcrList, PCRValue{
			Index: uint8(i),
			Value: pcr,
		})
	}

	return pcrList
}
