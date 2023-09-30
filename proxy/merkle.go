package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/cbergoon/merkletree"
	"github.com/miekg/dns"
	"hash"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

type ECDSASignature struct {
	R, S *big.Int
}

// Build a new response DNSResponse struct that stores DNSContext as well as the salt and hash
type DNSResponse struct {
	DNSContext *DNSContext // salt of 256 bits
	Salt       []byte
	Hash       []byte
}

type WaitingResponse struct {
	response *DNSResponse
	notifyCh chan int
}

type BatchedRequests struct {
	responses []WaitingResponse
}

type MerkleProof struct {
	MerkleRoot []byte
	Signature  []byte
	Proof      [][]byte
}

type MerkleProofB64 struct {
	MerkleRoot string
	Signature  string
	Proof      string
}

// Assuming you have the private key and public key for ecdsa
var privateKeyMerkle *ecdsa.PrivateKey
var publicKeyMerkle *ecdsa.PublicKey

var batchedResponsesCh = make(chan WaitingResponse, batchSize*safetyFactor) // trying to change to an unbuffered channel
var processingBatch sync.Mutex
var batchTimer *time.Timer
var batchedResponses = &BatchedRequests{
	responses: make([]WaitingResponse, 0, batchSize*safetyFactor), // initial capacity for better performance
}

const (
	safetyFactor          = 2
	batchSize             = 8192
	txtRecordTTL          = 60
	NotificationProcessed = 0
	hashesPerTxtRecord    = 4
	timeWindow            = 10 * time.Millisecond
	maxEncodedLength      = 255
	maxDnsUdpSize         = 512
	saltBits              = 128
	maxUdpSizeCheck       = false
)

func init() {
	var err error

	// Attempt to load private key from file.
	privateKeyMerkle, err = LoadPrivateKeyFromFile("private.pem")
	if err != nil {
		log.Info("Failed to load private key from file. Error: %v", err)
	} else {
		log.Info("Successfully loaded private key from file.")
	}

	// Attempt to load public key from file.
	publicKeyMerkle, err = LoadPublicKeyFromFile("public.pem")
	if err != nil {
		log.Error("Failed to load public key from file. Error: %v", err)
		// If private key is loaded successfully, use its public part.
		if privateKeyMerkle != nil {
			publicKeyMerkle = &privateKeyMerkle.PublicKey
			log.Info("Using the public part of the loaded private key.")
		}
	} else {
		log.Info("Successfully loaded public key from file.")
	}
}

// StartBatchingProcess starts the batching process. It listens on the batchedResponsesCh channel for incoming responses.
// When a request is received, it is added to the batch. When the timer expires, the batch is processed.
// This function does four things:
// 1. Starts a goroutine that listens on the batchedResponsesCh channel for incoming responses.
// 2. Starts a timer that triggers the processing of the batch.
// 3. When a request is received, it is added to the batch.
// 4. When the timer expires, it processes the batch.
func StartBatchingProcess() {
	go func() {
		log.Debug("[BATCH_PROCESS] Starting batching process...")
		for {
			waitingRes := <-batchedResponsesCh

			processingBatch.Lock()
			batchedResponses.responses = append(batchedResponses.responses, waitingRes)
			shouldProcess := false

			// Check if it's larger than the batch size, if so give an error
			if len(batchedResponses.responses) > batchSize {
				log.Error("[BATCH_PROCESS] Batch size exceeded max of %d, %d", batchSize, len(batchedResponses.responses))
			}

			// Check if we've accumulated enough requests for a batch, and if so, process them and reset timer
			if len(batchedResponses.responses) >= batchSize {
				if batchTimer != nil {
					batchTimer.Stop()
					batchTimer = nil
				}
				shouldProcess = true
			} else if batchTimer == nil {
				// Mark that we need to start the timer outside the lock
				shouldProcess = false
			}
			processingBatch.Unlock()

			if shouldProcess {
				go processBatch()
			} else if batchTimer == nil {
				batchTimer = time.AfterFunc(timeWindow, processBatch)
			}
		}
	}()
}

// MerkleAnsResponseHandler is the response handler for the Merkle batching process.
// It is called when a response is received from the upstream server. For every response received,
// it adds the response to the batch and waits for the batch to be processed.
// After the batch is processed, it updates the response with the Merkle proof.
func MerkleAnsResponseHandler(d *DNSContext, err error) {
	log.Debug("[BATCH_PROCESS] pocResponseHandler called for %s\n", d.Req.Question[0].Name)
	if err != nil {
		log.Debug("[BATCH_PROCESS] Error in DNS response: %s\n", err) // TODO: consider changing back to error
		return
	}

	// generate a salt
	salt := make([]byte, saltBits)
	_, err = rand.Read(salt)

	// Create a new DNSResponse struct
	dnsResponse := &DNSResponse{
		DNSContext: d,
		Salt:       salt,
	}
	dnsResponse.Hash, err = dnsResponse.CalculateHash()
	if err != nil {
		log.Error("[BATCH_PROCESS] Error calculating hash: %s\n", err)
		return
	}
	waitingRes := WaitingResponse{
		response: dnsResponse,
		notifyCh: make(chan int),
	}
	batchedResponsesCh <- waitingRes

	errCode := <-waitingRes.notifyCh // Block until we have the batch size
	if errCode != NotificationProcessed {
		log.Error("[BATCH_PROCESS] Error processing batch: %d\n", errCode)
		return
	}
}

func processBatch() {
	processingBatch.Lock()

	// Separate out the current batch and reset for the next batch
	currentBatch := batchedResponses.responses
	batchedResponses.responses = make([]WaitingResponse, 0, batchSize*safetyFactor)

	// Stop the batch timer if it's running
	if batchTimer != nil {
		batchTimer.Stop()
		batchTimer = nil
	}

	processingBatch.Unlock()
	// if the batch is empty, return
	if len(currentBatch) == 0 {
		processingBatch.Lock()
		if batchTimer == nil {
			batchTimer = time.AfterFunc(timeWindow, processBatch)
		}
		processingBatch.Unlock()
		return
	}
	// Time to process the batch! The first thing to do is construct the Merkle tree.
	// For simplicity, we will use the DNSContext as the Content for the Merkle tree.
	var contents []merkletree.Content
	for _, waitingRes := range currentBatch {
		contents = append(contents, waitingRes.response)
		log.Debug("[BATCH_PROCESS] Processing response: %s\n", waitingRes.response.DNSContext.Req.Question[0].Name)
	}
	proof := &MerkleProof{}
	// TODO: sort responses by source IP address
	// log length of contents
	log.Debug("[BATCH_PROCESS] Total responses in batch: %d\n", len(contents))
	tree, err := merkletree.NewTree(contents)
	if err != nil {
		log.Error("error creating merkle tree: %s", err)
		return
	}

	// Sign the Merkle root
	proof.MerkleRoot = []byte(tree.MerkleRoot())
	proof.Signature, err = createSignature(proof.MerkleRoot)
	if err != nil {
		log.Error("error signing merkle root: %s", err)
		return
	}

	// Notify all waiting responses of the batch size
	for _, waitingRes := range currentBatch {
		path, indexes, err := tree.GetMerklePath(waitingRes.response)
		if err != nil {
			log.Error("error getting merkle path: %s", err)
			continue
		}
		// Serialize and append the Merkle path and indexes
		proof.Proof, err = SerializePathAndIndexes(path, indexes)
		if err != nil {
			log.Error("error serializing merkle path and indexes: %s", err)
			continue
		}

		allEncodedData := encodeProofB64(&waitingRes, proof)
		packedData := PackStringsForTxtRecord(allEncodedData)

		AppendPackedDataAsTxtRecords(waitingRes, packedData)

		// log the response size
		log.Debug("[BATCH_PROCESS] Response size: %d\n", waitingRes.response.DNSContext.Res.Len())
		// log the length of the last TXT record
		log.Debug("[BATCH_PROCESS] Last TXT record length: %d\n", len(waitingRes.response.DNSContext.Res.Extra[len(waitingRes.response.DNSContext.Res.Extra)-1].String()))
		// TODO: handle oversized responses, truncate, separate TCP & UDP, all for next time
		// check that the DNS total length is less than 512 bytes if the protocol is UDP
		if waitingRes.response.DNSContext.Res.Len() > maxDnsUdpSize && maxUdpSizeCheck {
			log.Error("DNS response exceeds %d bytes, size is %d, there are %d requests in the batch", maxDnsUdpSize, waitingRes.response.DNSContext.Res.Len(), len(currentBatch))
			log.Debug("DNS response: %s", waitingRes.response.DNSContext.Res.String())
			// number of extra records is the number of proofs + 2 (for salt and signature)
			log.Debug("Number of extra records: %d", len(waitingRes.response.DNSContext.Res.Extra))
			// continue // TODO: handle this the DNS way by sending a truncated response
			// Send a truncated response
			waitingRes.response.DNSContext.Res.Truncated = true // TODO is this ok?
		}
		waitingRes.notifyCh <- NotificationProcessed
		close(waitingRes.notifyCh)
	}

	log.Debug("[BATCH_PROCESS] Finished processing batch. Clearing batch.")
	// batchedResponses.responses = batchedResponses.responses[:0]
	processingBatch.Lock()
	if batchTimer == nil {
		batchTimer = time.AfterFunc(timeWindow, processBatch)
	}
	processingBatch.Unlock()

}

func AppendPackedDataAsTxtRecords(waitingRes WaitingResponse, packedData []string) {
	extraLen := len(waitingRes.response.DNSContext.Res.Extra)
	totalTxtRecords := len(packedData)
	if cap(waitingRes.response.DNSContext.Res.Extra) < extraLen+totalTxtRecords {
		newExtra := make([]dns.RR, extraLen, extraLen+totalTxtRecords)
		copy(newExtra, waitingRes.response.DNSContext.Res.Extra)
		waitingRes.response.DNSContext.Res.Extra = newExtra
	}

	for _, packed := range packedData {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: waitingRes.response.DNSContext.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{packed},
		}
		waitingRes.response.DNSContext.Res.Extra = append(waitingRes.response.DNSContext.Res.Extra, rr)
	}
}

func encodeProofB64(waitingRes *WaitingResponse, proof *MerkleProof) []string {
	var allEncodedData []string

	// Encode salt and signature with colons
	allEncodedData = append(allEncodedData, base64.StdEncoding.EncodeToString(waitingRes.response.Salt)+":")
	allEncodedData = append(allEncodedData, base64.StdEncoding.EncodeToString(proof.Signature)+":")

	// Add the encoded proofs with colons
	for _, proofRecord := range proof.Proof {
		allEncodedData = append(allEncodedData, base64.StdEncoding.EncodeToString(proofRecord)+":")
	}
	return allEncodedData
}

// MerkleRrResponseHandler verifies the DNS response containing Merkle proof and signatures.
// It first extracts the proof and signature, then recreates the Merkle root from the proof,
// and finally verifies the signature using a known public key.
func MerkleRrResponseHandler(d *DNSContext, err error) {
	if err != nil {
		log.Debug("Error in DNS response: %s", err) // TODO: consider changing back to error
		return
	}
	// log the request
	log.Debug("[MerkleRR]: Request: %s", d.Req.String())
	// log the response
	log.Debug("[MerkleRR]: Response: %s", d.Res.String())
	// Extract the Merkle root, signature, and serialized proof from TXT records
	salt, signature, merkleProofSerialized, err := ExtractTXTData(d.Res.Extra)
	if err != nil {
		log.Error("Error extracting Merkle root, signature, and proof from DNS response: %s. %s", err, d.Res.Extra)
		return
	}

	// Deserialize the Merkle path and indexes
	path, indexes, err := DeserializeMerkleData(merkleProofSerialized)
	if err != nil {
		log.Error("Error deserializing Merkle path and indexes: %s", err)
		return
	}
	dres := &DNSResponse{
		DNSContext: d,
		Salt:       salt,
	}
	dres.Hash, err = dres.CalculateHash()
	if err != nil {
		log.Error("Error calculating hash: %s", err)
		return
	}

	// 3. Verify if the content is present using the extracted path.
	calculatedMerkleRoot, err := calculateMerkleRoot(dres, path, indexes, salt, sha256.New)
	if err != nil {
		log.Error("Error calculating Merkle root: %s", err)
		return
	}

	// 4. Verify the signature (Assuming you have a verifySignature function ready)
	if !verifySignature(calculatedMerkleRoot, []byte(signature)) {
		log.Error("Signature verification failed")
		return
	} else {
		log.Debug("Signature verification successful")
	}

	// 6. Match the domain of the response with the requested domain.
	if d.Req.Question[0].Name != d.Res.Question[0].Name {
		log.Error("Domain name mismatch between request and response")
		return
	}

	// If everything is fine, handle the response
	log.Debug("Verified DNS response successfully")
}

func ExtractTXTData(extra []dns.RR) ([]byte, []byte, [][]byte, error) {
	// Get all TXT record data
	var packedData []string
	for _, rr := range extra {
		if txt, ok := rr.(*dns.TXT); ok {
			packedData = append(packedData, txt.Txt[0])
		}
	}

	unpackedData := SplitConcatenatedBase64(strings.Join(packedData, ""))

	if len(unpackedData) < 2 {
		return nil, nil, nil, fmt.Errorf("salt, signature, or proof not found in DNS response")
	}

	// Extract salt and signature
	salt, signature := unpackedData[0], unpackedData[1]

	// The remaining data after salt and signature are the proofs
	serializedMerkleDataParts := unpackedData[2:]

	// Log values in their base64 encoded form for debugging
	log.Debug("Salt: %s", salt)
	log.Debug("Signature: %s", signature)
	for _, part := range serializedMerkleDataParts {
		log.Debug("Merkle proof part: %s", part)
	}

	// Decode the salt and signature from base64
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, nil, nil, err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, nil, err
	}

	// Decode the merkle data parts from base64
	var merkleDataParts [][]byte
	for _, part := range serializedMerkleDataParts {
		bytesPart, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			return nil, nil, nil, err
		}
		merkleDataParts = append(merkleDataParts, bytesPart)
	}

	// log the decoded values
	log.Debug("Salt Bytes: %x", saltBytes)
	log.Debug("Signature Bytes: %x", signatureBytes)
	for _, part := range merkleDataParts {
		log.Debug("Merkle proof part: %x", part)
	}
	return saltBytes, signatureBytes, merkleDataParts, nil
}

func verifySignature(hash []byte, signature []byte) bool {
	// Compute the SHA-256 hash of the data

	var rs ECDSASignature
	// Unmarshal the ASN.1 DER encoded signature
	if _, err := asn1.Unmarshal(signature, &rs); err != nil {
		log.Error("Failed to unmarshal signature: %s", err)
		return false
	}

	// Verify the signature
	if ecdsa.Verify(publicKeyMerkle, hash[:], rs.R, rs.S) {
		return true
	}

	return false
}

func LoadPrivateKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Error("Error reading private key file '%s'. Error: %v", filename, err)
		return nil, err
	}

	var block *pem.Block
	for {
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == "EC PRIVATE KEY" {
			privateKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				log.Error("Error parsing EC private key from '%s'. Error: %v", filename, err)
				return nil, err
			}
			return privateKey, nil
		}
	}

	log.Error("Failed to decode PEM block containing private key from '%s'", filename)
	return nil, errors.New("Failed to decode PEM block containing private key")
}

func LoadPublicKeyFromFile(filename string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Error("Error reading public key file '%s'. Error: %v", filename, err)
		return nil, err
	}

	var block *pem.Block
	for {
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == "PUBLIC KEY" {
			pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Error("Error parsing PKIX public key from '%s'. Error: %v", filename, err)
				return nil, err
			}

			publicKey, ok := pubInterface.(*ecdsa.PublicKey)
			if !ok {
				log.Error("Failed to assert public key from '%s' as ECDSA public key", filename)
				return nil, errors.New("Failed to assert as ECDSA public key")
			}

			return publicKey, nil
		}
	}

	log.Error("Failed to decode PEM block containing public key from '%s'", filename)
	return nil, errors.New("Failed to decode PEM block containing public key")
}

func createSignature(hash []byte) ([]byte, error) {
	// check to ensure that the private key is not nil
	if privateKeyMerkle == nil {
		// if it is, log error and panic
		log.Error("Private key is nil")
		panic("Private key is nil")
	}
	// Sign the data
	r, s, err := ecdsa.Sign(rand.Reader, privateKeyMerkle, hash[:])
	if err != nil {
		return nil, err
	}

	// Marshal the signature to ASN.1 DER format
	sig := ECDSASignature{R: r, S: s}
	sigASN1, err := asn1.Marshal(sig)
	if err != nil {
		return nil, err
	}

	return sigASN1, nil
}

func calculateMerkleRoot(dres *DNSResponse, merklePath [][]byte, indexes []int64, knownRootHashSignature []byte, hashStrategy func() hash.Hash) ([]byte, error) {
	log.Debug("Starting Merkle verification...")
	// log merkle path length
	log.Debug("Merkle path length: %d", len(merklePath))
	// log indexes
	log.Debug("Merkle path indexes: %d", indexes)
	// log known root hash
	log.Debug("Known root hash signature: %x", knownRootHashSignature)
	leafHash, err := dres.CalculateHash()
	if err != nil {
		log.Error("Error calculating leaf hash: %v", err)
		return nil, err
	}

	log.Debug("Calculated leaf hash: %x", leafHash)

	currentHash := leafHash
	for i, pathHash := range merklePath {
		h := hashStrategy()

		log.Debug("Iteration %d: Current hash: %x, Path hash: %x, Index: %d", i, currentHash, pathHash, indexes[i])

		if indexes[i] == 0 { // left leaf
			_, err = h.Write(append(pathHash, currentHash...))
			if err != nil {
				log.Error("Error writing to hash at iteration %d (left leaf): %v", i, err)
				return nil, err
			}
		} else { // right leaf
			_, err = h.Write(append(currentHash, pathHash...))
			if err != nil {
				log.Error("Error writing to hash at iteration %d (right leaf): %v", i, err)
				return nil, err
			}
		}

		currentHash = h.Sum(nil)
		log.Debug("New current hash at iteration %d: %x", i, currentHash)
	}
	return currentHash, nil
}

func (dres *DNSResponse) CalculateHash() ([]byte, error) {
	if dres.Hash != nil {
		// log the hash
		log.Debug("Skipped since hash is already calculated. Calculated hash for %s: %x", dres.DNSContext.Req.Question[0].Name, dres.Hash)
		return dres.Hash, nil
	}

	h := sha256.New()
	if _, err := h.Write(dres.Salt); err != nil {
		return nil, err
	}
	for _, question := range dres.DNSContext.Req.Question {
		if _, err := h.Write([]byte(question.String())); err != nil {
			return nil, err
		}

	}
	for _, answer := range dres.DNSContext.Res.Answer {
		if _, err := h.Write([]byte(answer.String())); err != nil {
			return nil, err
		}
	}
	// log the hash
	log.Debug("Calculated hash for %s: %x", dres.DNSContext.Req.Question[0].Name, h.Sum(nil))
	// log salt
	log.Debug("Salt for %s: %x", dres.DNSContext.Req.Question[0].Name, dres.Salt)
	return h.Sum(nil), nil
}

func (dres *DNSResponse) Equals(other merkletree.Content) (bool, error) {
	otherContent, ok := other.(*DNSResponse)
	if !ok {
		return false, errors.New("value is not of type DNSResponse")
	}

	if dres.Hash == nil {
		dres.Hash, _ = dres.CalculateHash()
	}

	if otherContent.Hash == nil {
		otherContent.Hash, _ = otherContent.CalculateHash()
	}

	return bytes.Equal(dres.Hash, otherContent.Hash), nil
}

func SerializePathAndIndexes(path [][]byte, indexes []int64) ([][]byte, error) {
	var serializedData [][]byte

	// 1. Serialize indexes
	indexBuffer := new(bytes.Buffer)
	indexEncoder := gob.NewEncoder(indexBuffer)
	if err := indexEncoder.Encode(indexes); err != nil {
		return nil, err
	}
	serializedData = append(serializedData, indexBuffer.Bytes())

	// 2. Serialize each individual hash in the path
	for _, hash := range path {
		hashBuffer := new(bytes.Buffer)
		hashEncoder := gob.NewEncoder(hashBuffer)
		if err := hashEncoder.Encode(hash); err != nil {
			return nil, err
		}
		serializedData = append(serializedData, hashBuffer.Bytes())
	}

	return serializedData, nil
}

func DeserializeMerkleData(records [][]byte) ([][]byte, []int64, error) {
	var path [][]byte
	var indexes []int64

	// First record is for indexes
	indexDecoder := gob.NewDecoder(bytes.NewBuffer(records[0]))
	if err := indexDecoder.Decode(&indexes); err != nil {
		return nil, nil, fmt.Errorf("error deserializing Merkle indexes: %s", err)
	}

	// Subsequent records are for the hashes
	for _, record := range records[1:] {
		var hash []byte
		hashDecoder := gob.NewDecoder(bytes.NewBuffer(record))
		if err := hashDecoder.Decode(&hash); err != nil {
			return nil, nil, fmt.Errorf("error deserializing Merkle path: %s", err)
		}
		path = append(path, hash)
	}

	return path, indexes, nil
}

func PackStringsForTxtRecord(strs []string) []string {
	result := make([]string, 0)
	buffer := ""

	for _, str := range strs {
		remainingLength := maxEncodedLength - len(buffer)
		if len(str) <= remainingLength {
			buffer += str
		} else {
			// Append the part of the string that fits
			buffer += str[:remainingLength]
			result = append(result, buffer)

			// Reset buffer and process the remainder of the string
			buffer = str[remainingLength:]
		}

		if len(buffer) == maxEncodedLength {
			result = append(result, buffer)
			buffer = ""
		}
	}

	if buffer != "" {
		result = append(result, buffer)
	}

	return result
}

func SplitConcatenatedBase64(packedDataString string) []string {
	// Splitting the concatenated data by colon
	allParts := strings.Split(packedDataString, ":")

	// Filtering out any potential empty strings due to trailing colons
	filteredParts := make([]string, 0, len(allParts))
	for _, part := range allParts {
		if part != "" {
			filteredParts = append(filteredParts, part)
		}
	}

	return filteredParts
}
