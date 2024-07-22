package proxy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"fmt"
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

// DNSResponse Build a new response struct that stores DNSContext as well as the salt and hash
type DNSResponse struct {
	DNSContext *DNSContext // salt of 256 bits
	Salt       []byte
	Hash       []byte
}

type WaitingResponse struct {
	response  *DNSResponse
	notifyCh  chan int
	processed bool
}

type BatchedResponses struct {
	responses []WaitingResponse
}

type MerkleProof struct {
	Signature []byte
	Proof     [][]byte
}

type MerkleProofB64 struct {
	MerkleRoot string
	Signature  string
	Proof      string
}

// Assuming you have the private key and public key for ecdsa
var privateKeyMerkle *ecdsa.PrivateKey
var publicKeyMerkle *ecdsa.PublicKey
var privateKeyRSA *rsa.PrivateKey
var publicKeyRSA *rsa.PublicKey

var responsesReceived = 0
var responsesProcessed = 0
var batchedResponsesCh = make(chan WaitingResponse, batchSize*safetyFactor)
var collectingMutex sync.Mutex
var processingMutex sync.Mutex
var batchTimer *time.Timer
var collectingResponses = &BatchedResponses{
	responses: make([]WaitingResponse, 0, batchSize*safetyFactor), // initial capacity for better performance
}
var processingResponses = &BatchedResponses{
	responses: make([]WaitingResponse, 0, batchSize*safetyFactor), // initial capacity for better performance
}
var longestTime = 0 * time.Millisecond
var signatureCache = sync.Map{}

type cacheKey struct {
	Hash      [32]byte
	Signature string
}

var batchSize int
var timeWindow time.Duration
var UseRSA bool

const (
	safetyFactor          = 2
	txtRecordTTL          = 60
	NotificationProcessed = 0
	maxEncodedLength      = 255
	maxDnsUdpSize         = 4096
	saltBits              = 128
	maxUdpSizeCheck       = true
)

func init() {
	var err error

	// Attempt to load private key from file.
	privateKeyMerkle, err = LoadECDSAPrivateKeyFromFile("private.pem")
	if err != nil {
		log.Info("Failed to load private key from file. Error: %v", err)
	} else {
		log.Info("Successfully loaded private key from file.")
	}

	// Attempt to load public key from file.
	publicKeyMerkle, err = LoadECDSAPublicKeyFromFile("public.pem")
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
	// Attempt to load private RSA key from file.
	privateKeyRSA, err = LoadRSAPrivateKeyFromFile("rsa_private.pem")
	if err != nil {
		log.Info("Failed to load RSA private key from file. Error: %v", err)
	} else {
		log.Info("Successfully loaded RSA private key from file.")
	}
	// Attempt to load public RSA key from file.
	publicKeyRSA, err = LoadRSAPublicKeyFromFile("rsa_public.pem")
	if err != nil {
		log.Error("Failed to load RSA public key from file. Error: %v", err)
	} else {
		log.Info("Successfully loaded RSA public key from file.")
	}

}

func handleBatch() {
	log.Debug("[BATCH_PROCESS] Handling batch... locking collecting mutex")
	collectingMutex.Lock()
	log.Debug("[BATCH_PROCESS] Handling batch... locking processing mutex")
	processingMutex.Lock()
	swapBuffers()

	if batchTimer != nil {
		log.Debug("[BATCH_PROCESS] handleBatch: stopping timer")
		batchTimer.Stop()
		batchTimer = nil
	}

	log.Debug("[BATCH_PROCESS] handleBatch: unlocking processing mutex")
	processingMutex.Unlock()
	log.Debug("[BATCH_PROCESS] handleBatch: unlocking collecting mutex")
	collectingMutex.Unlock()

	go processBatch()
}

// StartBatchingProcess starts the batching process. It listens on the batchedResponsesCh channel for incoming responses.
// When a request is received, it is added to the batch. When the timer expires, the batch is processed.
// This function does four things:
// 1. Starts a goroutine that listens on the batchedResponsesCh channel for incoming responses.
// 2. Starts a timer that triggers the processing of the batch.
// 3. When a request is received, it is added to the batch.
// 4. When the timer expires, it processes the batch.
func StartBatchingProcess(
	_batchSize int,
	_timeWindow time.Duration,
	_useRSA bool) {
	timeWindow = _timeWindow
	batchSize = _batchSize
	UseRSA = _useRSA
	go func() {
		log.Debug("[BATCH_PROCESS] Starting batching process...")
		for {
			waitingRes := <-batchedResponsesCh
			//log.Debug("[BATCH_PROCESS] Received response, locking collecting mutex", waitingRes.response.DNSContext.Req.Question[0].Name)
			collectingMutex.Lock()
			//log.Debug("collecting mutex locked")
			collectingResponses.responses = append(collectingResponses.responses, waitingRes)
			//log.Debug("[BATCH_PROCESS] unlocking collecting mutex", waitingRes.response.DNSContext.Req.Question[0].Name)
			collectingMutex.Unlock()
			shouldProcess := false

			// Check for batch size exceeding
			if len(collectingResponses.responses) >= batchSize {
				shouldProcess = true
			} else if batchTimer == nil {
				// We'll start the timer after unlocking.
				shouldProcess = false
			}

			if shouldProcess {
				handleBatch()
			} else if batchTimer == nil {
				log.Debug("[BATCH_PROCESS] StartBatchingProcess Starting timer")
				batchTimer = time.AfterFunc(timeWindow, handleBatch)
			}
		}
	}()
}

// MerkleAnsResponseHandler is the response handler for the Merkle batching process.
// It is called when a response is received from the upstream server. For every response received,
// it adds the response to the batch and waits for the batch to be processed.
// After the batch is processed, it updates the response with the Merkle proof.
func MerkleAnsResponseHandler(d *DNSContext, err error) {

	// increment responses received
	responsesReceived++
	// log number of responses received
	log.Debug("[MerkleAns]: Responses received: %d", responsesReceived)
	responseTime := time.Now()
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
		response:  dnsResponse,
		notifyCh:  make(chan int),
		processed: false,
	}
	batchedResponsesCh <- waitingRes

	errCode := <-waitingRes.notifyCh // Block until we have the batch size
	if errCode != NotificationProcessed {
		log.Error("[BATCH_PROCESS] Error processing batch: %d\n", errCode)
		return
	}
	responseEnd := time.Now()
	// increment responses processed
	responsesProcessed++
	// log number of responses processed
	log.Debug("[MerkleAns]: Responses processed: %d", responsesProcessed)
	log.Debug("[BATCH_PROCESS] Response time. Start: %d, End: %d, Delta: %d\n", responseTime.UnixNano(), responseEnd.UnixNano(), responseEnd.Sub(responseTime))
	if responseEnd.Sub(responseTime) > longestTime {
		longestTime = responseEnd.Sub(responseTime)
		log.Debug("[BATCH_PROCESS] Longest response time so far: %d\n", longestTime)
	}
}

func swapBuffers() {
	// No locks in here

	// Swap the buffers
	collectingResponses, processingResponses = processingResponses, collectingResponses
	collectingResponses.responses = collectingResponses.responses[:0]
}

func processBatch() {
	batchId := time.Now().UnixNano()
	log.Debug("[BATCH_PROCESS] Processing batch %d... attempting to lock processing mutex", batchId)
	processingMutex.Lock()
	log.Debug("[BATCH_PROCESS] Processing batch %d... processing mutex locked", batchId)
	defer processingMutex.Unlock()
	var contents []merkletree.Content
	for _, waitingRes := range processingResponses.responses {
		contents = append(contents, waitingRes.response)
		log.Debug("[BATCH_PROCESS] Processing response: %s\n", waitingRes.response.DNSContext.Req.Question[0].Name)
	}
	if len(contents) == 0 {
		log.Debug("[BATCH_PROCESS] No responses in batch, mutex unlocked")
		return
	}
	proof := &MerkleProof{}
	// log length of contents
	log.Debug("[BATCH_PROCESS] Total responses in batch: %d\n", len(contents))
	tree, err := merkletree.NewTree(contents)
	if err != nil {
		log.Error("error creating merkle tree: %s", err)
		return
	}

	// Sign the Merkle root
	proof.Signature, err = createSignature(tree.MerkleRoot())
	if err != nil {
		log.Error("error signing merkle root: %s", err)
		return
	}
	// log batch size
	log.Debug("[BATCH_PROCESS] Batch size: %d\n", len(processingResponses.responses))
	// Notify all waiting responses of the batch size
	for _, waitingRes := range processingResponses.responses {
		if waitingRes.processed {
			log.Error("response already processed")
			continue
		}
		waitingRes.processed = true
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

		allEncodedData := encodeProofB64(waitingRes.response.Salt, proof)
		packedData := PackStringsForTxtRecord(allEncodedData)

		// Assuming `waitingRes` and `packedData` are defined earlier in your code
		newTxtRecords := CreateTxtRecordsForPackedData(waitingRes.response.DNSContext.Req.Question[0].Name, packedData)

		// Check capacity and expand if necessary
		extraLen := len(waitingRes.response.DNSContext.Res.Extra)
		totalTxtRecords := len(newTxtRecords)
		if cap(waitingRes.response.DNSContext.Res.Extra) < extraLen+totalTxtRecords {
			newExtra := make([]dns.RR, extraLen, extraLen+totalTxtRecords)
			copy(newExtra, waitingRes.response.DNSContext.Res.Extra)
			waitingRes.response.DNSContext.Res.Extra = newExtra
		}
		waitingRes.response.DNSContext.Res.Extra = append(waitingRes.response.DNSContext.Res.Extra, newTxtRecords...)

		// TODO: handle oversized responses, truncate, separate TCP & UDP, all for next time
		// check that the DNS total length is less than 512 bytes if the protocol is UDP
		if waitingRes.response.DNSContext.Res.Len() > maxDnsUdpSize && maxUdpSizeCheck {
			log.Error("error: DNS response exceeds %d bytes, size is %d, there are %d requests in the batch", maxDnsUdpSize, waitingRes.response.DNSContext.Res.Len(), len(processingResponses.responses))
			waitingRes.response.DNSContext.Res.Truncated = true
		}
		waitingRes.notifyCh <- NotificationProcessed
		close(waitingRes.notifyCh)
	}
	processingResponses.responses = processingResponses.responses[:0]
	log.Debug("[BATCH_PROCESS] Batch %d processed, mutex unlocked", batchId)
}

func CreateTxtRecordsForPackedData(domain string, packedData []string) []dns.RR {
	var txtRecords []dns.RR
	for _, packed := range packedData {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{packed},
		}
		txtRecords = append(txtRecords, rr)
	}
	return txtRecords
}

func encodeProofB64(salt []byte, proof *MerkleProof) []string {
	var allEncodedData []string

	// Encode salt and signature with colons
	allEncodedData = append(allEncodedData, base64.StdEncoding.EncodeToString(salt)+":")
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

	// 4. Verify the signature
	if !verifySignature(calculatedMerkleRoot, signature) {
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
	key := cacheKey{
		Hash:      [32]byte(hash),
		Signature: string(signature),
	}

	if result, found := signatureCache.Load(key); found {
		return result.(bool)
	}

	var verificationResult bool
	if UseRSA {
		if publicKeyRSA == nil {
			log.Error("RSA public key is nil")
			return false
		}
		err := rsa.VerifyPKCS1v15(publicKeyRSA, crypto.SHA256, hash, signature)
		verificationResult = err == nil
	} else {
		if publicKeyMerkle == nil {
			log.Error("ECDSA public key is nil")
			return false
		}
		var rs ECDSASignature
		_, err := asn1.Unmarshal(signature, &rs)
		if err != nil {
			log.Error("Failed to unmarshal ECDSA signature: %s", err)
			return false
		}
		verificationResult = ecdsa.Verify(publicKeyMerkle, hash, rs.R, rs.S)
	}

	signatureCache.Store(key, verificationResult)
	return verificationResult
}

func LoadECDSAPrivateKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing ECDSA private key")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

func LoadECDSAPublicKeyFromFile(filename string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing ECDSA public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return pubKey, nil
}

func LoadRSAPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file '%s': %v", filename, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Try to parse PKCS1 first
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}

	// Try to parse PKCS8 if PKCS1 parsing fails
	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		privateKey, ok := privateKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
		return privateKey, nil
	}

	return nil, fmt.Errorf("failed to parse RSA private key")
}

// LoadRSAPublicKeyFromFile loads an RSA public key from a file.
func LoadRSAPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file '%s': %v", filename, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing PKIX public key: %v", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return pubKey, nil
}

func createSignature(hash []byte) ([]byte, error) {
	if UseRSA {
		if privateKeyRSA == nil {
			log.Error("RSA private key is nil")
			panic("RSA private key is nil")
		}
		// Use SHA256 hash for RSA signing
		return rsa.SignPKCS1v15(rand.Reader, privateKeyRSA, crypto.SHA256, hash)
	} else {
		if privateKeyMerkle == nil {
			log.Error("ECDSA private key is nil")
			panic("ECDSA private key is nil")
		}
		r, s, err := ecdsa.Sign(rand.Reader, privateKeyMerkle, hash)
		if err != nil {
			return nil, err
		}
		sig := ECDSASignature{R: r, S: s}
		return asn1.Marshal(sig)
	}
}

func calculateMerkleRoot(dres *DNSResponse, merklePath [][]byte, indexes []int64, knownRootHashSignature []byte, hashStrategy func() hash.Hash) ([]byte, error) {
	log.Debug("Starting Merkle verification...")
	// log merkle path length
	log.Debug("Merkle path length: %d", len(merklePath))
	// log indexes
	log.Debug("Merkle path indexes: %d", indexes)
	// log known root hash
	log.Debug("Known root hash signature: %x", knownRootHashSignature)
	var err error
	if dres.Hash == nil {
		if dres.Hash, err = dres.CalculateHash(); err != nil {
			log.Error("Error calculating hash for DNSResponse: %v", err)
			return nil, err
		}
	}
	leafHash := dres.Hash

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
	h.Write(dres.Salt) // Ignore error since h.Write() never fails

	for _, question := range dres.DNSContext.Req.Question {
		h.Write([]byte(question.String())) // Ignore error
	}

	for _, answer := range dres.DNSContext.Res.Answer {
		h.Write([]byte(answer.String())) // Ignore error
	}

	hashedValue := h.Sum(nil)
	// log the hash
	log.Debug("Calculated hash for %s: %x", dres.DNSContext.Req.Question[0].Name, hashedValue)
	// log salt
	log.Debug("Salt for %s: %x", dres.DNSContext.Req.Question[0].Name, dres.Salt)

	dres.Hash = hashedValue
	return hashedValue, nil
}

func (dres *DNSResponse) Equals(other merkletree.Content) (bool, error) {
	otherContent, ok := other.(*DNSResponse)
	if !ok {
		return false, fmt.Errorf("value is not of type DNSResponse")
	}

	var err error
	if dres.Hash == nil {
		dres.Hash, err = dres.CalculateHash()
		if err != nil {
			log.Error("Error calculating hash for DNSResponse: %v", err)
			return false, err
		}
	}

	if otherContent.Hash == nil {
		otherContent.Hash, err = otherContent.CalculateHash()
		if err != nil {
			log.Error("Error calculating hash for other DNSResponse: %v", err)
			return false, err
		}
	}

	return bytes.Equal(dres.Hash, otherContent.Hash), nil
}

func SerializePathAndIndexes(path [][]byte, indexes []int64) ([][]byte, error) {
	serializedData := make([][]byte, len(path)+1)

	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)

	// 1. Serialize indexes
	if err := encoder.Encode(indexes); err != nil {
		return nil, err
	}
	serializedData[0] = append(serializedData[0], buf.Bytes()...)
	buf.Reset()

	// 2. Serialize each individual hash in the path
	for i, stepHash := range path {
		if err := encoder.Encode(stepHash); err != nil {
			return nil, err
		}
		serializedData[i+1] = append(serializedData[i+1], buf.Bytes()...)
		buf.Reset()
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
		var recordHash []byte
		hashDecoder := gob.NewDecoder(bytes.NewBuffer(record))
		if err := hashDecoder.Decode(&recordHash); err != nil {
			return nil, nil, fmt.Errorf("error deserializing Merkle path: %s", err)
		}
		path = append(path, recordHash)
	}

	return path, indexes, nil
}

func PackStringsForTxtRecord(strs []string) []string {
	result := make([]string, 0)
	buffer := ""
	for _, str := range strs {
		remainingLength := maxEncodedLength - len(buffer)
		for len(buffer) > maxEncodedLength {
			result = append(result, buffer[:maxEncodedLength])
			buffer = buffer[maxEncodedLength:]
			remainingLength = maxEncodedLength - len(buffer)
		}

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
