package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
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

const batchRequestChanSize = 256
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
		// Attach the Merkle root
		merkleRootRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: waitingReq.response.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{string(merkleRootHash)},
		}
		waitingReq.response.Res.Extra = append(waitingReq.response.Res.Extra, merkleRootRR)

		// Attach the signature
		signatureRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: waitingReq.response.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{string(merkleSignature)},
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

//type BatchedResponse struct {
//	Responses  []*DNSContext
//	MerklePath [][]byte // Added MerklePath field
//	LeafIndex  []int64  // Added LeafIndex field
//}

func (dctx DNSContext) Serialize() ([]byte, error) {
	// Convert the DNSContext (or parts of it) to a byte slice.
	// For simplicity, let's just serialize the DNS messages. You can expand on this.
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	if err := encoder.Encode(dctx.Req); err != nil {
		return nil, err
	}
	if err := encoder.Encode(dctx.Res); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// New function to serialize Merkle path and indexes
func serializePathAndIndexes(path [][]byte, indexes []int64) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	if err := encoder.Encode(path); err != nil {
		return nil, err
	}
	if err := encoder.Encode(indexes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func ExportPublicKeyToPEM(pubkey *ecdsa.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubBytes,
		},
	)
	return pubPEM, nil
}

func deserializeMerkleData(merkleProofSerialized string) ([][]byte, []int64, error) {
	var path [][]byte
	var indexes []int64
	buf := bytes.NewBufferString(merkleProofSerialized)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(&path); err != nil {
		return nil, nil, fmt.Errorf("Error deserializing Merkle path: %s", err)
	}
	if err := decoder.Decode(&indexes); err != nil {
		return nil, nil, fmt.Errorf("Error deserializing Merkle indexes: %s", err)
	}
	return path, indexes, nil
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

	// Deserialize the Merkle path and indexes
	path, indexes, err := deserializeMerkleData(merkleProofSerialized)
	if err != nil {
		log.Error("Error deserializing Merkle path and indexes: %s", err)
		return
	}

	buf := bytes.NewBufferString(merkleProofSerialized)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(&path); err != nil {
		log.Error("Error deserializing Merkle path: %s", err)
		return
	}
	if err := decoder.Decode(&indexes); err != nil {
		log.Error("Error deserializing Merkle indexes: %s", err)
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

func extractTXTData(extra []dns.RR) ([]byte, string, string, error) {
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
		return nil, "", "", fmt.Errorf("Merkle root, signature, or proof not found in DNS response")
	}
	return []byte(merkleRoot), signature, merkleProofSerialized, nil
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
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Printf("Failed to decode PEM block containing private key from '%s'", filename)
		return nil, errors.New("Failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Printf("Error parsing EC private key from '%s'. Error: %v", filename, err)
		return nil, err
	}

	return privateKey, nil
}

func LoadPublicKeyFromFile(filename string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading public key file '%s'. Error: %v", filename, err)
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "EC PUBLIC KEY" {
		log.Printf("Failed to decode PEM block containing public key from '%s'", filename)
		return nil, errors.New("Failed to decode PEM block containing public key")
	}

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

type ECDSASignature struct {
	R, S *big.Int
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
	leafHash, err := dctx.CalculateHash()
	if err != nil {
		return false, err
	}

	currentHash := leafHash
	for i, pathHash := range merklePath {
		h := hashStrategy()

		if indexes[i] == 0 { // left leaf
			_, err := h.Write(append(pathHash, currentHash...))
			if err != nil {
				return false, err
			}
		} else { // right leaf
			_, err := h.Write(append(currentHash, pathHash...))
			if err != nil {
				return false, err
			}
		}

		currentHash = h.Sum(nil)
	}

	return bytes.Equal(currentHash, knownRootHash), nil
}
