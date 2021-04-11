package logger

import (
	"fmt"
	"bytes"
	"strings"
	"encoding/json"
	"net/http"
	"math/rand"
	"os"
	"io/ioutil"
	ba "github.com/Workiva/go-datastructures/bitarray"
	mtr "github.com/n-ct/ct-monitor"
	el "github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/signature"
	"github.com/google/certificate-transparency-go/tls"
	ca "github.com/n-ct/ct-certificate-authority/ca"
	ctca "github.com/n-ct/ct-certificate-authority"
)

const (
	GetLogSRDWithRevDataPath  =	"/ct/v1/get-log-srd-with-rev-data"
	PostLogSRDWithRevDataPath = "/ct/v1/post-log-srd-with-rev-data"
	RevokeAndProduceSRDPath   = "/ct/v1/revoke-and-produce-srd"
)

//type to hold data and functionality of a Relying Party
type Logger struct {
	//map to store the LogSRDWithRevData structs, map[CA ID][Revocation Type]
	LogSRDWithRevDataMap	map[string] map[string] *mtr.SRDWithRevData
	//map to store the CurrentCRV as a bitarray, map[CA ID][Revocation Type]
	CurrentCRVMap			map[string] map[string] ba.BitArray
	Port 					string
	Address					string
	LogID					string
	Signer 					*signature.Signer
	PublicKey				string
	CAList 					*el.CAList
}

type LoggerConfig struct {
	LogID	string `json:"log_id"`
	PrivKey	string `json:"private_key"`
	URL		string `json:"url"`
	Key 	string `json:"key"`
}

func parseLoggerConfig(fileName string) (*LoggerConfig, error){

	jsonFile, err := os.Open(fileName)
	defer jsonFile.Close()
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	//fmt.Printf("Successfully Opened %s\n", fileName)
	byteData, err := ioutil.ReadAll(jsonFile)

	if err != nil {
		return nil, fmt.Errorf("error parsing logger config: %w", err)
	}
	var config LoggerConfig
	err = json.Unmarshal(byteData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal logger config: %w", err)
	}
	return &config, nil
}

//creates and returns a new Relying party type
func NewLogger(configName, caListName string) (*Logger, error){
	caList, err := el.NewCAList(caListName)
	if err != nil {
		return nil, err
	}

	config, err := parseLoggerConfig(configName)
	if err != nil {
		return nil, err
	}

	URL := config.URL
	if URL[len(URL)-1] == '/' { //if the last char of the url is a '/' remove it
		URL = URL[0:len(URL)-1]
	}
	URL = URL[0:strings.LastIndex(URL, "/")] //remove everything after the last '/'

	signer,err := signature.NewSigner(config.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("error creating signer for logger: %v", err)
	}

	logger := &Logger{
		Port:		"6966",
		Address:	"localhost", //set to local host for testing, should be set to URL
		LogID: 		config.LogID,
		Signer:		signer,
		PublicKey:	config.Key,
		CAList:		caList,
	}
	return logger, nil
}

func (this *Logger) createNewMMDSRDWithRevData(data *mtr.SRDWithRevData) (*mtr.SRDWithRevData, error) {
	newSRD := &data.SRD //cast the CTObject to a SRD
	newRevData := &data.RevData //cast the CTObject to a RevData
	caID := newSRD.EntityID
	caInfo := this.CAList.FindCAByCAID(caID)
	if caInfo == nil {
		return nil, fmt.Errorf("caID (%v) not found in caInfoMap", caID)
	}
	caKey := caInfo.CAKey

	err := ca.VerifySRDSignature(newSRD, caKey) //verify the signature on the object
	if err != nil {
		return nil, fmt.Errorf("Invalid signature: %v", err) // if there is an eror report
	}

	deltaCRV, err := ctca.DecompressCRV(newRevData.CRVDelta) //decompress the delta CRV
	if err != nil {
		return nil, fmt.Errorf("Invalid compression on delta CRV: %v", err) // if there is an eror report
	}

	if this.CurrentCRVMap == nil { //if this is the first post request made
		this.CurrentCRVMap = make(map[string]map[string] ba.BitArray)
	}
	if this.CurrentCRVMap[newSRD.EntityID] == nil { //if this is the first post request made by this entity
		this.CurrentCRVMap[newSRD.EntityID] = make(map[string] ba.BitArray)
		this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] = ba.NewBitArray((*deltaCRV).Capacity()) // create a new bit array the same size as the deltaCRV
	}

	currentCRV := this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] //get the current CRV, with the current rev type for the requesting ca

	NewCRV := ctca.ApplyCRVDeltaToCRV(&currentCRV, deltaCRV) //apply the delta crv to the crv

	compCRV, err := ctca.CompressCRV(NewCRV) //compress and hash the new CRV to make sure it is consistant
	crvHash, _, err := signature.GenerateHash(tls.SHA256, compCRV)
	if err != nil {
		return nil, fmt.Errorf("Error Hashing CRV: %v", err) // if there is an eror report
	}

	if bytes.Compare(newSRD.RevDigest.CRVHash, crvHash) == 0 { //if delta CRV is consistant
		this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] = *NewCRV //update the curr CRV
	} else {
		return nil, fmt.Errorf("Inconsistant delta CRV: %v + %v", newSRD.RevDigest.CRVHash, crvHash) // if there is an eror report
	}

	newMMDSRD, err := ca.CreateSRDWithRevData(
		&currentCRV, deltaCRV,
		newSRD.RevDigest.Timestamp,
		this.LogID,
		tls.SHA256,
		this.Signer,
	)
	return newMMDSRD, err
}

func (this *Logger) UpdateLogSRDWithRevData(data *mtr.SRDWithRevData) error {
	newSRDWithRevData, err := this.createNewMMDSRDWithRevData(data)
	if err != nil {
		return fmt.Errorf("failed to create newMMDSRD: %w", err)
	}
	newSRD := &data.SRD //cast the CTObject to a SRD
	newRevData := &data.RevData //cast the CTObject to a RevData

	if this.LogSRDWithRevDataMap == nil {
		this.LogSRDWithRevDataMap = make(map[string]map[string] *mtr.SRDWithRevData)
	}
	if this.LogSRDWithRevDataMap[newSRD.EntityID] == nil {
		this.LogSRDWithRevDataMap[newSRD.EntityID] = make(map[string] *mtr.SRDWithRevData)
	}

	//update the SRDWithRevDataMap
	this.LogSRDWithRevDataMap[newSRD.EntityID][newRevData.RevocationType] = newSRDWithRevData
	if err != nil {
		return fmt.Errorf("Error Updating SRDWithRevData: %v", err) // if there is an eror report
	}
	this.LogSRDWithRevDataMap[newSRD.EntityID][newRevData.RevocationType].RevData.RevocationType = "Let's-Revoke" //update the revocation type
	return nil //if get to the end ther are no errors
}

/*func (this *Logger) UpdateLogSRDWithRevData(data *mtr.SRDWithRevData) error {
	newSRD := &data.SRD //cast the CTObject to a SRD
	newRevData := &data.RevData //cast the CTObject to a RevData
	caID := newSRD.EntityID
	caInfo := this.CAList.FindCAByCAID(caID)
	if caInfo == nil {
		return fmt.Errorf("caID (%v) not found in caInfoMap", caID)
	}
	caKey := caInfo.CAKey

	err := ca.VerifySRDSignature(newSRD, caKey) //verify the signature on the object
	if err != nil {
		return fmt.Errorf("Invalid signature: %v", err) // if there is an eror report
	}

	deltaCRV, err := ctca.DecompressCRV(newRevData.CRVDelta) //decompress the delta CRV
	if err != nil {
		return fmt.Errorf("Invalid compression on delta CRV: %v", err) // if there is an eror report
	}

	if this.CurrentCRVMap == nil { //if this is the first post request made
		this.CurrentCRVMap = make(map[string]map[string] ba.BitArray)
	}
	if this.CurrentCRVMap[newSRD.EntityID] == nil { //if this is the first post request made by this entity
		this.CurrentCRVMap[newSRD.EntityID] = make(map[string] ba.BitArray)
		this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] = ba.NewBitArray((*deltaCRV).Capacity()) // create a new bit array the same size as the deltaCRV
	}

	currentCRV := this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] //get the current CRV, with the current rev type for the requesting ca

	NewCRV := ctca.ApplyCRVDeltaToCRV(&currentCRV, deltaCRV) //apply the delta crv to the crv

	compCRV, err := ctca.CompressCRV(NewCRV) //compress and hash the new CRV to make sure it is consistant
	crvHash, _, err := signature.GenerateHash(tls.SHA256, compCRV)
	if err != nil {
		return fmt.Errorf("Error Hashing CRV: %v", err) // if there is an eror report
	}

	if bytes.Compare(newSRD.RevDigest.CRVHash, crvHash) == 0 { //if delta CRV is consistant
		this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] = *NewCRV //update the curr CRV
	} else {
		return fmt.Errorf("Inconsistant delta CRV: %v + %v", newSRD.RevDigest.CRVHash, crvHash) // if there is an eror report
	}

	if this.LogSRDWithRevDataMap == nil {
		this.LogSRDWithRevDataMap = make(map[string]map[string] *mtr.SRDWithRevData)
	}
	if this.LogSRDWithRevDataMap[newSRD.EntityID] == nil {
		this.LogSRDWithRevDataMap[newSRD.EntityID] = make(map[string] *mtr.SRDWithRevData)
	}

	//update the SRDWithRevDataMap
	this.LogSRDWithRevDataMap[newSRD.EntityID][newRevData.RevocationType], err = ca.CreateSRDWithRevData(
		&currentCRV, deltaCRV,
		newSRD.RevDigest.Timestamp,
		this.LogID,
		tls.SHA256,
		this.Signer,
	)

	if err != nil {
		return fmt.Errorf("Error Updating SRDWithRevData: %v", err) // if there is an eror report
	}
	this.LogSRDWithRevDataMap[newSRD.EntityID][newRevData.RevocationType].RevData.RevocationType = "Let's-Revoke" //update the revocation type
	return nil //if get to the end ther are no errors
}
*/

func (this *Logger) OnPostLogSRDWithRevData(res http.ResponseWriter, req *http.Request) {
	data := mtr.SRDWithRevData{}; //create an empty CTObject
	err := json.NewDecoder(req.Body).Decode(&data); // fill that struct using the JSON encoded struct send via the Post
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid data sent via post: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	err = this.UpdateLogSRDWithRevData(&data); //update with the given data
	if err != nil {
		http.Error(res, fmt.Sprintf("Unable to Update: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
}

func (this *Logger) GetAllLogSrdWithRevDataAsJSONBytes() ([]byte,error) {
	if this.LogSRDWithRevDataMap == nil { //if the SRDmap hasnt been created yet report that to the caller and return
		return nil, fmt.Errorf("SRDWithRevData is still being created")
	}

	var CTObjects = []mtr.CTObject{} //create an empty slice to hold ctobjects

	for _, element := range this.LogSRDWithRevDataMap {
		LogSRDWithRevData := element["Let's-Revoke"]
		CTObject, err := mtr.ConstructCTObject(LogSRDWithRevData)
		if err != nil {
			return nil, fmt.Errorf("Error Generating LogSRD objects: %v", err) // if there is an eror report
		}
		CTObjects = append(CTObjects, *CTObject)
	}

	var jsonBytes, err = json.Marshal(CTObjects)
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal CTObjects: %v", err) // if there is an eror report
	}
	return jsonBytes, nil
}

func (this *Logger) OnGetLogSRDWithRevData(res http.ResponseWriter, req *http.Request) {
	jsonBytes, err := this.GetAllLogSrdWithRevDataAsJSONBytes()
	if err != nil {
		http.Error(res, fmt.Sprintf("%v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	res.Write(jsonBytes)
}

func (this *Logger) OnRevokeAndProduceSRD(res http.ResponseWriter, req *http.Request) {
	data := ctca.RevokeAndProduceSRDRequest{}; //create an empty CTObject
	err := json.NewDecoder(req.Body).Decode(&data); // fill that struct using the JSON encoded struct send via the Post
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid data sent via post: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	ca := this.GetRandomCAInfoFromCaList()
	if err != nil {
		http.Error(res, fmt.Sprintf("No CAs to forward message to"), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	//fmt.Println(data)
	jsonBytes, err := json.Marshal(data)	// Just use serialize method somewhere else
	caReq, err := http.NewRequest("GET", fmt.Sprintf("%v%v", ca.CAURL, RevokeAndProduceSRDPath), bytes.NewBuffer(jsonBytes))
	client := &http.Client{};
	caResp, err := client.Do(caReq);
	if err != nil {
		panic(err);
	}
	defer caResp.Body.Close();
	//body, err := ioutil.ReadAll(caResp.Body)
	caData := mtr.SRDWithRevData{}; //create an empty CTObject
	err = json.NewDecoder(caResp.Body).Decode(&caData); // fill that struct using the JSON encoded struct send via the Post
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid data sent via post: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	newLogSRD, err := this.createNewMMDSRDWithRevData(&caData)
	if err != nil {
		http.Error(res, fmt.Sprintf("failed to create SRD in Logger: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	newLogSRDBytes, err := json.Marshal(newLogSRD)	// Just use serialize method somewhere else

	res.Write(newLogSRDBytes)
}

func (this *Logger) GetRandomCAInfoFromCaList() (*el.CAInfo){
	ops := this.CAList.CAOperators
	if len(ops) > 0 {
		opIndex := rand.Intn(len(ops))
		cas := ops[opIndex].CAs
		if len(cas) > 0 {
		 	caIndex := rand.Intn(len(cas))
		 	return cas[caIndex]
		}
	}
	return nil;
}
