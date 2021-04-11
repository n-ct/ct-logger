package logger

import (
	"testing"
	"encoding/json"
	"fmt"
	"bytes"
	//"net/http"
	"time"
	mtr "github.com/n-ct/ct-monitor"
	ctca "github.com/n-ct/ct-certificate-authority"
	ca "github.com/n-ct/ct-certificate-authority/ca"
	"github.com/Workiva/go-datastructures/bitarray"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/n-ct/ct-monitor/signature"
)
//"ca_id": "LeYXK29QzQV9RxvgMw+hnOeyZV85A6a5quOLltev9H0=",
//"ca_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmFk6QT48Ts4oxSkBPM4mQ/mnWICKVmZUP6urQVBH0vhDzJVYHc2ShvF2KjWzorVu2C+tY6lIU+61iiPLsGvZXw==",
const (
	//config_filename string = "config.json"
	config_filename string = "../testdata/config.json"
	//caList_filename string = "C:\\Users\\Eli\\go\\src\\ct-logger\\logger\\ca_list.json"
	caList_filename string = "../testdata/ca_list.json"
	ca_id			string = "LeYXK29QzQV9RxvgMw+hnOeyZV85A6a5quOLltev9H0="
	private_key		string = "MHcCAQEEIOWK47/9gxKjcpTe8UhL4PyXZS1lPcnqChRvlw/Jpnh0oAoGCCqGSM49AwEHoUQDQgAEmFk6QT48Ts4oxSkBPM4mQ/mnWICKVmZUP6urQVBH0vhDzJVYHc2ShvF2KjWzorVu2C+tY6lIU+61iiPLsGvZXw=="

)

//https://localhost:6966/ct/v1/post-log-srd-with-rev-data

//function that returns a new logger type, or an error if creation fails
func mustCreateLogger(t *testing.T) (*Logger, error){
	t.Helper()
	logger, err := NewLogger(config_filename, caList_filename)
	return logger, err
}

//function to test creating a new logger
func TestNewLogger(t *testing.T) {
	_, err := mustCreateLogger(t)
	if err != nil {
		t.Fatalf("failed to create Logger with config @ (%s): %v", config_filename, err)
	}
}

//function that returns a new signer type, or an error if creation fails
func mustCreateSigner(t *testing.T) (*signature.Signer, error){
	signer,err := signature.NewSigner(private_key)
	if err != nil {
		return nil, fmt.Errorf("error creating signer for logger: %v", err)
	}
	return signer, nil;
}

func mustUpdateLogSRDWithRevData(t *testing.T, logger *Logger, crv, deltaCRV *bitarray.BitArray) (error){
	compCRV, err := ctca.CompressCRV(deltaCRV)
	crvHash, _, err := signature.GenerateHash(tls.SHA256, compCRV)

	var timestamp uint64 = uint64(time.Now().Unix())
	signer, err := mustCreateSigner(t);
	if err != nil {
		return fmt.Errorf("failed to create signer: %v", err)
	}

	srdWithRevData, err := ca.CreateSRDWithRevData(crv, deltaCRV, timestamp, ca_id, tls.SHA256, signer)

	err = logger.UpdateLogSRDWithRevData(srdWithRevData)

	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if logger.LogSRDWithRevDataMap == nil {
		return fmt.Errorf("LogSRDWithRevDataMap not initialized")
	}
	if logger.LogSRDWithRevDataMap[ca_id] == nil {
		return fmt.Errorf("LogSRDWithRevDataMap[ca_id] not initialized")
	}
	if logger.LogSRDWithRevDataMap[ca_id]["Let's-Revoke"] == nil {
		return fmt.Errorf("LogSRDWithRevDataMap[ca_id][\"Let's-Revoke\"] not initialized")
	}
	if !(logger.LogSRDWithRevDataMap[ca_id]["Let's-Revoke"].RevData.Timestamp==timestamp) {
		return fmt.Errorf("invalid timestamp in LogSRDWithRevDataMap")
	}
	if !(bytes.Compare(logger.LogSRDWithRevDataMap[ca_id]["Let's-Revoke"].SRD.RevDigest.CRVDeltaHash, crvHash)==0) {
		return fmt.Errorf("invalid CRVDeltaHash in LogSRDWithRevDataMap")
	}
	if !(logger.LogSRDWithRevDataMap[ca_id]["Let's-Revoke"].SRD.EntityID==logger.LogID) {
		return fmt.Errorf("invalid EntityID in LogSRDWithRevDataMap")
	}
	return nil
}

//function to test updating the log SRDWithRevData map in the logger
func TestUpdateLogSRDWithRevData(t *testing.T) {
	logger, _ := mustCreateLogger(t)

	crv := ctca.CreateCRV([]uint64{1,3}, 0) // == 101
	deltaCRV := ctca.GetCRVDelta([]uint64{1,3}) //000 ==> 101

	err := mustUpdateLogSRDWithRevData(t, logger, crv, deltaCRV)

	if err != nil {
		t.Fatalf("logger not updated correctly 1: %v", err)
	}

	crv2 := ctca.CreateCRV([]uint64{1,3,4,5,7}, 0) //==> 1011 1010
	deltaCRV2 := ctca.GetCRVDelta([]uint64{4,5,7}) // 111 ==> 1011 1010

	err = mustUpdateLogSRDWithRevData(t, logger, crv2, deltaCRV2)

	if err != nil {
		t.Fatalf("logger not updated correctly 2: %v", err)
	}
}

func TestGetAllLogSrdWithRevDataAsJSONBytes(t *testing.T) {
	logger, _ := mustCreateLogger(t)

	_,err := logger.GetAllLogSrdWithRevDataAsJSONBytes()
	if err == nil {
		t.Fatalf("logger not returning error on invalid request: %v", err)
	}

	crv := ctca.CreateCRV([]uint64{1,3}, 0) // == 101
	deltaCRV := ctca.GetCRVDelta([]uint64{1,3}) //000 ==> 101

	mustUpdateLogSRDWithRevData(t, logger, crv, deltaCRV)

	crv2 := ctca.CreateCRV([]uint64{1,3,4,5,7}, 0) //==> 1011 1010
	deltaCRV2 := ctca.GetCRVDelta([]uint64{4,5,7}) // 111 ==> 1011 1010

	mustUpdateLogSRDWithRevData(t, logger, crv2, deltaCRV2)

	jsonBytes,err := logger.GetAllLogSrdWithRevDataAsJSONBytes()
	if err != nil {
		t.Fatalf("failed to get LogSRDWithRevDataMap as string: %v", err)
	}
	var revDataList []mtr.CTObject
	err = json.Unmarshal(jsonBytes, &revDataList)
	if err != nil {
		t.Fatalf("failed to unmarshal bytes from logger: %v", err)
	}

	if(len(revDataList) != 1) {
		t.Fatalf("returned list should be of size 1 not %v", len(revDataList))
	}
	_,err = revDataList[0].DeconstructSRD()
	if(err != nil) {
		t.Fatalf("invalid type in returned list: %v", err)
	}
	_,err = revDataList[0].DeconstructRevData()
	if(err != nil) {
		t.Fatalf("invalid type in returned list: %v", err)
	}
}

func TestOnRevokeAndProduceSRD(t *testing.T) {
	logger, _ := mustCreateLogger(t)
	_,err := logger.GetAllLogSrdWithRevDataAsJSONBytes()
	if err == nil {
		t.Fatalf("logger not returning error on invalid request: %v", err)
	}
	crv := ctca.CreateCRV([]uint64{1,3}, 0) // == 101
	deltaCRV := ctca.GetCRVDelta([]uint64{1,3}) //000 ==> 101
	mustUpdateLogSRDWithRevData(t, logger, crv, deltaCRV)
}
