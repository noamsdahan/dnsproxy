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
	_, _, strs, _ := generateSampleData()

	packed := PackStringsForTxtRecord(strs)
	split := SplitConcatenatedBase64(strings.Join(packed, ""))

	if !reflect.DeepEqual(strs, split) {
		t.Errorf("Original and split strings do not match")
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

	// 2. Serialize the proof path and indexes
	serializedPath, err := SerializePathAndIndexes(originalPath, originalIndexes)
	if err != nil {
		t.Fatalf("Error in SerializePathAndIndexes: %s", err)
	}

	// 3. Base64 encode all the generated data
	encodedSalt := base64.StdEncoding.EncodeToString(originalSalt)
	encodedSignature := base64.StdEncoding.EncodeToString(originalSignature)
	encodedProofParts := make([]string, len(serializedPath))
	for i, part := range serializedPath {
		encodedProofParts[i] = base64.StdEncoding.EncodeToString(part)
	}

	// 4. Pack them into TXT records
	allEncodedStrings := append([]string{encodedSalt, encodedSignature}, encodedProofParts...)
	packedForTXT := PackStringsForTxtRecord(allEncodedStrings)
	txtRRs := make([]dns.RR, len(packedForTXT))
	for i, packedData := range packedForTXT {
		txtRRs[i] = &dns.TXT{
			Txt: []string{packedData},
		}
	}

	// 5. Extract the data from TXT records
	extractedSalt, extractedSignature, extractedProofSerialized, err := ExtractTXTData(txtRRs)
	if err != nil {
		t.Fatalf("Error in ExtractTXTData: %s", err)
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
