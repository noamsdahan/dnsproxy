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
	"sync"
	"time"
)

type ECDSASignature struct {
	R, S *big.Int
}

type WaitingResponse struct {
	response *DNSContext
	notifyCh chan int
}

type BatchedRequests struct {
	responses []WaitingResponse
}

// Assuming you have the private key and public key for ecdsa
var privateKey *ecdsa.PrivateKey
var publicKey *ecdsa.PublicKey

var batchedRequestsCh = make(chan WaitingResponse, batchRequestChanSize) // A buffered channel for simplicity
var processingBatch sync.Mutex
var batchTimer *time.Timer
var batchedResponses = &BatchedRequests{
	responses: make([]WaitingResponse, 0, batchRequestChanSize), // initial capacity for better performance
}

const batchRequestChanSize = 128
const txtRecordTTL = 60
const NotificationProcessed = 0

// Just key initialization for initial testing TODO: remove and simplify
func init() {
	var err error

	// Attempt to load private key from file.
	privateKey, err = LoadPrivateKeyFromFile("private.pem")
	if err != nil {
		log.Printf("Failed to load private key from file. Error: %v", err)
	} else {
		log.Println("Successfully loaded private key from file.")
	}

	// Attempt to load public key from file.
	publicKey, err = LoadPublicKeyFromFile("public.pem")
	if err != nil {
		log.Printf("Failed to load public key from file. Error: %v", err)
		// If private key is loaded successfully, use its public part.
		if privateKey != nil {
			publicKey = &privateKey.PublicKey
			log.Println("Using the public part of the loaded private key.")
		}
	} else {
		log.Println("Successfully loaded public key from file.")
	}
}

// StartBatchingProcess starts the batching process. It listens on the batchedRequestsCh channel for incoming responses.
// When a request is received, it is added to the batch. When the timer expires, the batch is processed.
// This function does four things:
// 1. Starts a goroutine that listens on the batchedRequestsCh channel for incoming responses.
// 2. Starts a timer that triggers the processing of the batch.
// 3. When a request is received, it is added to the batch.
// 4. When the timer expires, it processes the batch.
func StartBatchingProcess() {
	go func() {
		log.Debug("[BATCH_PROCESS] Starting batching process...")
		for {
			waitingRes := <-batchedRequestsCh // Block until a request is received
			// Lock to ensure only one batch is processed at a time
			processingBatch.Lock()

			if batchTimer == nil { // If the timer is not running, start it
				// Start the timer for 80ms
				log.Debug("[BATCH_PROCESS] Starting timer for 80ms...")
				batchTimer = time.AfterFunc(80*time.Millisecond, processBatch)
			}

			// Add the request to the batch
			batchedResponses.responses = append(batchedResponses.responses, waitingRes)
			// log.Debug("[BATCH_PROCESS] Added request to batch. Total responses in batch: %d\n", len(batchedResponses.responses))
			processingBatch.Unlock()
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
		log.Error("[BATCH_PROCESS] Error in DNS response: %s\n", err)
		return
	}

	waitingRes := WaitingResponse{
		response: d,
		notifyCh: make(chan int),
	}
	batchedRequestsCh <- waitingRes

	batchSize := <-waitingRes.notifyCh // Block until we have the batch size
	log.Debug("[BATCH_PROCESS] This batch had a size of: %d\n", batchSize)
	// TODO: Use batchSize to update the response. Replace this comment with your response updating logic.
}

func processBatch() {
	processingBatch.Lock()
	defer processingBatch.Unlock()

	// Time to process the batch! The first thing to do is construct the Merkle tree.
	// For simplicity, we will use the DNSContext as the Content for the Merkle tree.
	var contents []merkletree.Content
	for _, waitingReq := range batchedResponses.responses {
		contents = append(contents, waitingReq.response)
		log.Debug("[BATCH_PROCESS] Processing response: %s\n", waitingReq.response.Req.Question[0].Name)
	}
	// TODO: sort responses by source IP address
	// log length of contents
	log.Debug("[BATCH_PROCESS] Total responses in batch: %d\n", len(contents))
	tree, err := merkletree.NewTree(contents)
	if err != nil {
		log.Error("error creating merkle tree: %s", err)
		return
	}

	// Sign the Merkle root
	merkleRootHash := []byte(tree.MerkleRoot())
	merkleSignature, err := createSignature(merkleRootHash)
	if err != nil {
		log.Error("error signing merkle root: %s", err)
		return
	}

	// merkleSignature is now a byte slice containing the ASN.1 DER encoded signature.
	// You can encode it to a string format like hex or base64 if needed.

	// Notify all waiting responses of the batch size
	for _, waitingReq := range batchedResponses.responses {
		path, indexes, err := tree.GetMerklePath(waitingReq.response)
		if err != nil {
			log.Error("error getting merkle path: %s", err)
			continue
		}
		// Serialize and append the Merkle path and indexes
		proofBytes, err := serializePathAndIndexes(path, indexes)
		if err != nil {
			log.Error("error serializing merkle path and indexes: %s", err)
			continue
		}
		debugVerificationTest := true
		if debugVerificationTest {
			// Verify if the content is present using the extracted path.
			ok, err := verifyMerklePath(waitingReq.response, path, indexes, merkleRootHash, sha256.New)
			if err != nil || !ok {
				log.Error("Error or mismatch in Merkle verification: %s", err)
				continue
			}
		}
		// encode the merkle root hash and signature to base64
		merkleRootHashBase64 := base64.StdEncoding.EncodeToString(merkleRootHash)
		merkleSignatureBase64 := base64.StdEncoding.EncodeToString(merkleSignature)
		// Attach the Merkle root
		merkleRootRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: waitingReq.response.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{merkleRootHashBase64},
		}
		waitingReq.response.Res.Extra = append(waitingReq.response.Res.Extra, merkleRootRR)

		// Attach the signature
		signatureRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: waitingReq.response.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{string(merkleSignatureBase64)},
		}
		waitingReq.response.Res.Extra = append(waitingReq.response.Res.Extra, signatureRR)

		proofRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: waitingReq.response.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{string(proofBytes)},
		}
		waitingReq.response.Res.Extra = append(waitingReq.response.Res.Extra, proofRR)
		waitingReq.notifyCh <- NotificationProcessed
		close(waitingReq.notifyCh)
	}

	log.Debug("[BATCH_PROCESS] Finished processing batch. Clearing batch.")
	batchedResponses.responses = make([]WaitingResponse, 0, batchRequestChanSize) // re-initialize the slice with initial capacity
	batchTimer = nil
}

// MerkleRrResponseHandler verifies the DNS response containing Merkle proof and signatures.
// It first extracts the proof and signature, then recreates the Merkle root from the proof,
// and finally verifies the signature using a known public key.
func MerkleRrResponseHandler(d *DNSContext, err error) {
	if err != nil {
		log.Error("Error in DNS response: %s", err)
		return
	}

	// Extract the Merkle root, signature, and serialized proof from TXT records
	knownRootHash, signature, merkleProofSerialized, err := extractTXTData(d.Res.Extra)
	if err != nil {
		log.Error("Error extracting Merkle root, signature, and proof from DNS response: %s", err)
		return
	}

	// Log the serialized Merkle data
	log.Debug("Serialized Merkle Data: %s", merkleProofSerialized)

	// Deserialize the Merkle path and indexes
	path, indexes, err := deserializeMerkleData(merkleProofSerialized)
	if err != nil {
		log.Error("Error deserializing Merkle path and indexes: %s", err)
		return
	}

	// 3. Verify if the content is present using the extracted path.
	ok, err := verifyMerklePath(d, path, indexes, knownRootHash, sha256.New)
	if err != nil || !ok {
		log.Error("Error or mismatch in Merkle verification: %s", err)
		return
	}

	// 4. Verify the signature (Assuming you have a verifySignature function ready)
	if !verifySignature(knownRootHash, []byte(signature)) {
		log.Error("Signature verification failed")
		return
	}

	// 6. Match the domain of the response with the requested domain.
	if d.Req.Question[0].Name != d.Res.Question[0].Name {
		log.Error("Domain name mismatch between request and response")
		return
	}

	// If everything is fine, handle the response
	log.Debug("Verified DNS response successfully")
}

func extractTXTData(extra []dns.RR) ([]byte, []byte, []byte, error) {
	var merkleRoot, signature, merkleProofSerialized string

	for _, rr := range extra {
		if txt, ok := rr.(*dns.TXT); ok {
			switch {
			case merkleRoot == "":
				merkleRoot = txt.Txt[0]
			case signature == "":
				signature = txt.Txt[0]
			default:
				merkleProofSerialized = txt.Txt[0]
				break
			}
		}
	}

	if merkleRoot == "" || signature == "" || merkleProofSerialized == "" {
		return nil, nil, nil, fmt.Errorf("Merkle root, signature, or proof not found in DNS response")
	}
	// log all 3 values in their base64 encoded form for debugging
	log.Debug("Merkle root: %s", merkleRoot)
	log.Debug("Signature: %s", signature)
	log.Debug("Merkle proof: %s", merkleProofSerialized)

	// decode the merkle root and signature from base64
	merkleRootBytes, err := base64.StdEncoding.DecodeString(merkleRoot)
	if err != nil {
		return nil, nil, nil, err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, nil, err
	}
	merkleProofSerializedBytes, err := base64.StdEncoding.DecodeString(merkleProofSerialized)
	return merkleRootBytes, signatureBytes, merkleProofSerializedBytes, nil
}

func verifySignature(hash []byte, signature []byte) bool {
	// Compute the SHA-256 hash of the data

	var rs ECDSASignature
	// Unmarshal the ASN.1 DER encoded signature
	if _, err := asn1.Unmarshal(signature, &rs); err != nil {
		log.Println("Failed to unmarshal signature:", err)
		return false
	}

	// Verify the signature
	if ecdsa.Verify(publicKey, hash[:], rs.R, rs.S) {
		return true
	}

	return false
}

func LoadPrivateKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading private key file '%s'. Error: %v", filename, err)
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
				log.Printf("Error parsing EC private key from '%s'. Error: %v", filename, err)
				return nil, err
			}
			return privateKey, nil
		}
	}

	log.Printf("Failed to decode PEM block containing private key from '%s'", filename)
	return nil, errors.New("Failed to decode PEM block containing private key")
}

func LoadPublicKeyFromFile(filename string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading public key file '%s'. Error: %v", filename, err)
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
				log.Printf("Error parsing PKIX public key from '%s'. Error: %v", filename, err)
				return nil, err
			}

			publicKey, ok := pubInterface.(*ecdsa.PublicKey)
			if !ok {
				log.Printf("Failed to assert public key from '%s' as ECDSA public key", filename)
				return nil, errors.New("Failed to assert as ECDSA public key")
			}

			return publicKey, nil
		}
	}

	log.Printf("Failed to decode PEM block containing public key from '%s'", filename)
	return nil, errors.New("Failed to decode PEM block containing public key")
}

func createSignature(hash []byte) ([]byte, error) {
	// check to ensure that the private key is not nil
	if privateKey == nil {
		// if it is, log error and panic
		log.Error("Private key is nil")
		panic("Private key is nil")
	}
	// Sign the data
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
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

func verifyMerklePath(dctx *DNSContext, merklePath [][]byte, indexes []int64, knownRootHash []byte, hashStrategy func() hash.Hash) (bool, error) {
	log.Debug("Starting Merkle verification...")
	// log merkle path length
	log.Debug("Merkle path length: %d", len(merklePath))
	// log indexes
	log.Debug("Merkle path indexes: %d", indexes)
	// log known root hash
	log.Debug("Known root hash: %x", knownRootHash)
	leafHash, err := dctx.CalculateHash()
	if err != nil {
		log.Error("Error calculating leaf hash: %v", err)
		return false, err
	}

	log.Debug("Calculated leaf hash: %x", leafHash)

	currentHash := leafHash
	for i, pathHash := range merklePath {
		h := hashStrategy()

		log.Debug("Iteration %d: Current hash: %x, Path hash: %x, Index: %d", i, currentHash, pathHash, indexes[i])

		if indexes[i] == 0 { // left leaf
			_, err := h.Write(append(pathHash, currentHash...))
			if err != nil {
				log.Error("Error writing to hash at iteration %d (left leaf): %v", i, err)
				return false, err
			}
		} else { // right leaf
			_, err := h.Write(append(currentHash, pathHash...))
			if err != nil {
				log.Error("Error writing to hash at iteration %d (right leaf): %v", i, err)
				return false, err
			}
		}

		currentHash = h.Sum(nil)
		log.Debug("New current hash at iteration %d: %x", i, currentHash)
	}

	isEqual := bytes.Equal(currentHash, knownRootHash)
	if !isEqual {
		log.Error("Merkle verification mismatch. Expected root hash: %x, Calculated hash: %x", knownRootHash, currentHash)
	}
	return isEqual, nil
}

// CalculateHash computes the hash of the DNSContext.
// It hashes the serialized representation of both the request and the response.
func (dctx *DNSContext) CalculateHash() ([]byte, error) {
	h := sha256.New()

	// Serialize and hash the request
	reqBytes, err := dctx.Req.Pack()
	if err != nil {
		return nil, err
	}
	_, err = h.Write(reqBytes)
	if err != nil {
		return nil, err
	}

	// Serialize and hash the response
	resBytes, err := dctx.Res.Pack()
	if err != nil {
		return nil, err
	}
	_, err = h.Write(resBytes)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals checks if two DNSContexts are equivalent.
// This function checks equality based on the serialized representations of the DNS messages.
func (dctx *DNSContext) Equals(other merkletree.Content) (bool, error) {
	otherContent, ok := other.(*DNSContext)
	if !ok {
		return false, errors.New("value is not of type DNSContext")
	}

	dReqBytes, err := dctx.Req.Pack()
	if err != nil {
		return false, err
	}

	otherReqBytes, err := otherContent.Req.Pack()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(dReqBytes, otherReqBytes) {
		return false, nil
	}

	dResBytes, err := dctx.Res.Pack()
	if err != nil {
		return false, err
	}

	otherResBytes, err := otherContent.Res.Pack()
	if err != nil {
		return false, err
	}

	return bytes.Equal(dResBytes, otherResBytes), nil
}

// New function to serialize Merkle path and indexes
func serializePathAndIndexes(path [][]byte, indexes []int64) (string, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	if err := encoder.Encode(path); err != nil {
		return "", err
	}
	if err := encoder.Encode(indexes); err != nil {
		return "", err
	}

	// Base64 encode the serialized data before returning
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func deserializeMerkleData(merkleProofBytes []byte) ([][]byte, []int64, error) {

	buf := bytes.NewBuffer(merkleProofBytes)
	decoder := gob.NewDecoder(buf)

	var path [][]byte
	var indexes []int64

	if err := decoder.Decode(&path); err != nil {
		return nil, nil, fmt.Errorf("Error deserializing Merkle path: %s", err)
	}
	if err := decoder.Decode(&indexes); err != nil {
		return nil, nil, fmt.Errorf("Error deserializing Merkle indexes: %s", err)
	}

	return path, indexes, nil
}
