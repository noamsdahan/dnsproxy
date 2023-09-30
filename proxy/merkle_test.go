package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/miekg/dns"
	"reflect"
	"strings"
	"testing"
)

const (
	hashSize   = 32
	pathLength = 8
)

func generateSampleData() ([][]byte, []int64, []string, []dns.RR) {
	path := [][]byte{
		[]byte("hash1"),
		[]byte("hash2"),
		[]byte("hash3"),
	}
	indexes := []int64{1, 2, 3}
	strs := []string{"sample1", "sample2", "sample3"}
	extra := []dns.RR{
		&dns.TXT{
			Txt: []string{base64.StdEncoding.EncodeToString([]byte("salt")) + ":" + base64.StdEncoding.EncodeToString([]byte("signature")) + ":" + base64.StdEncoding.EncodeToString([]byte("merkleDataPart1"))},
		},
	}
	return path, indexes, strs, extra
}

func TestSerializationAndDeserialization(t *testing.T) {
	path, indexes, _, _ := generateSampleData()

	serialized, err := SerializePathAndIndexes(path, indexes)
	if err != nil {
		t.Fatalf("Serialization failed: %v", err)
	}

	deserializedPath, deserializedIndexes, err := DeserializeMerkleData(serialized)
	if err != nil {
		t.Fatalf("Deserialization failed: %v", err)
	}

	if !reflect.DeepEqual(path, deserializedPath) || !reflect.DeepEqual(indexes, deserializedIndexes) {
		t.Errorf("Original and deserialized data do not match")
	}
}

func TestPackAndSplit(t *testing.T) {
	// generate random proof
	//random hash
	proof := &MerkleProof{
		Signature: []byte(generateRandomBytes(hashSize)),
		Proof: [][]byte{
			// random hash
			[]byte(generateRandomBytes(hashSize)),
			[]byte(generateRandomBytes(hashSize)),
			[]byte(generateRandomBytes(hashSize)),
		},
	}

	// generate random salt of 128 bits
	salt := generateRandomBytes(16)
	allEncodedData := encodeProofB64(salt, proof)
	packedData := PackStringsForTxtRecord(allEncodedData)
	split := SplitConcatenatedBase64(strings.Join(packedData, ""))
	if len(split) != 5 {
		t.Errorf("Split string does not have the correct number of parts")
	}
	salt_recieved, signature := split[0], split[1]

	// The remaining data after salt and signature are the proofs
	serializedMerkleDataParts := split[2:]
	if salt_recieved != base64.StdEncoding.EncodeToString(salt) {
		t.Errorf("Salt does not match")
	}
	if signature != base64.StdEncoding.EncodeToString(proof.Signature) {
		t.Errorf("Signature does not match")
	}
	for i, part := range serializedMerkleDataParts {
		if part != base64.StdEncoding.EncodeToString(proof.Proof[i]) {
			t.Errorf("Proof part %d does not match", i)
		}
	}
}

func TestExtractTXTData(t *testing.T) {
	_, _, _, extra := generateSampleData()

	salt, sig, merkleDataParts, err := ExtractTXTData(extra)
	if err != nil {
		t.Fatalf("Failed to extract TXT data: %v", err)
	}

	if string(salt) != "salt" || string(sig) != "signature" || len(merkleDataParts) != 1 || string(merkleDataParts[0]) != "merkleDataPart1" {
		t.Errorf("Extracted data does not match expected values")
	}
}

func TestEndToEndTXTRecordProcessing(t *testing.T) {
	// 1. Generate random mock data
	originalSalt := generateRandomBytes(hashSize)
	originalSignature := generateRandomBytes(hashSize)

	originalPath := make([][]byte, pathLength)
	for i := range originalPath {
		originalPath[i] = generateRandomBytes(hashSize)
	}

	originalIndexes := make([]int64, pathLength)
	for i := range originalIndexes {
		originalIndexes[i] = int64(i + 1)
	}
	proofOriginal := &MerkleProof{
		Signature: originalSignature,
	}
	// 2. Serialize the proof path and indexes
	var err error
	proofOriginal.Proof, err = SerializePathAndIndexes(originalPath, originalIndexes)
	if err != nil {
		t.Fatalf("Error in SerializePathAndIndexes: %s", err)
	}

	// 3. Base64 encode all the generated data

	// 4. Pack them into TXT records
	allEncodedData := encodeProofB64(originalSalt, proofOriginal)
	packedForTXT := PackStringsForTxtRecord(allEncodedData)
	txtRRs := CreateTxtRecordsForPackedData("example.com", packedForTXT)

	// 5. Extract the data from TXT records
	extractedSalt, extractedSignature, extractedProofSerialized, err := ExtractTXTData(txtRRs)
	if err != nil {
		t.Fatalf("Error in ExtractTXTData: %s. txtRRs: %+v", err, txtRRs)
	}

	// 6. Decode and deserialize the data
	extractedPath, extractedIndexes, err := DeserializeMerkleData(extractedProofSerialized)
	if err != nil {
		t.Fatalf("Error in DeserializeMerkleData: %s", err)
	}

	// 7. Assert that the original data and the final data are the same
	if string(originalSalt) != string(extractedSalt) {
		t.Fatalf("Mismatch in salt. Expected: %s, Got: %s", originalSalt, extractedSalt)
	}
	if string(originalSignature) != string(extractedSignature) {
		t.Fatalf("Mismatch in signature. Expected: %s, Got: %s", originalSignature, extractedSignature)
	}
	if !reflect.DeepEqual(originalIndexes, extractedIndexes) {
		t.Fatalf("Mismatch in indexes. Expected: %+v, Got: %+v", originalIndexes, extractedIndexes)
	}
	if !reflect.DeepEqual(originalPath, extractedPath) {
		t.Fatalf("Mismatch in paths. Expected: %+v, Got: %+v", originalPath, extractedPath)
	}
}

func generateRandomBytes(i int) []byte {
	b := make([]byte, i)
	_, _ = rand.Read(b)
	return b

}
