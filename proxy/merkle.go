package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/cbergoon/merkletree"
	"github.com/miekg/dns"
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

var batchedRequestsCh = make(chan WaitingResponse, 256) // A buffered channel for simplicity
var processingBatch sync.Mutex
var batchTimer *time.Timer
var batchedResponses = &BatchedRequests{
	responses: make([]WaitingResponse, 0, 256), // initial capacity for better performance
}

const txtRecordTTL = 60
const NotificationProcessed = 0

// Just key initialization for initial testing TODO: remove and simplify
func init() {
	privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey = &privateKey.PublicKey

	// Usage:
	pemBytes, err := ExportPublicKeyToPEM(publicKey)
	if err != nil {
		log.Fatalf("Error exporting public key: %v", err)
	}

	// If you want to write it to a file
	err = os.WriteFile("publicKey.pem", pemBytes, 0644)
	if err != nil {
		log.Fatalf("Error writing public key to file: %v", err)
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

// MerkleResponseHandler is the response handler for the Merkle batching process.
// It is called when a response is received from the upstream server. For every response received,
// it adds the response to the batch and waits for the batch to be processed.
// After the batch is processed, it updates the response with the Merkle proof.
func MerkleResponseHandler(d *DNSContext, err error) {
	log.Debug("[BATCH_PROCESS] pocResponseHandler called for %s\n", d.Req.Question[0].Name)

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
	hash := sha256.Sum256([]byte(tree.MerkleRoot()))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		log.Error("error signing merkle root: %s", err)
		return
	}
	merkleSignature := r.String() + s.String()

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
		// Attach the signature
		signatureRR := &dns.TXT{
			Hdr: dns.RR_Header{Name: waitingReq.response.Req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtRecordTTL},
			Txt: []string{merkleSignature},
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
	batchedResponses.responses = make([]WaitingResponse, 0, 100) // re-initialize the slice with initial capacity
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
