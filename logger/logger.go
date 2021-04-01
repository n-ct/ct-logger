package relyingparty

import (
	"fmt"
	"bytes"
	"strings"
	"encoding/json"
	"net/http"
	"github.com/n-ct/ct-monitor/utils"
	ba "github.com/Workiva/go-datastructures/bitarray"
	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/signature"
	"github.com/google/certificate-transparency-go/tls"
	ca "github.com/n-ct/ct-certificate-authority/ca"
	ctca "github.com/n-ct/ct-certificate-authority"
)

const (
	GetLogSRDWithRevDataPath =	"/ct/v1/get-log-srd-with-rev-data"
	PostLogSRDWithRevDataPath = "/ct/v1/post-log-srd-with-rev-data"
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
}

type LoggerConfig struct {
	LogID	string `json:"LogID"`
	PrivKey	string `json:"private_key"`
}

func parseLoggerConfig(fileName string) (*LoggerConfig, error){
	byteData, err := utils.FiletoBytes(fileName)
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
func NewLogger(logListName, configName string) (*Logger, error){
	logList, err := entitylist.NewLogList(logListName)

	config, err := parseLoggerConfig(configName)
	if err != nil {
		return nil, err
	}

	logInfo := logList.FindLogByLogID(config.LogID)
	if logInfo == nil {
		return nil, fmt.Errorf("Invalid LogID for logger\n")
	}

	URL := logInfo.URL
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
	}
	return logger, nil
}

func (this *Logger) OnPostLogSRDWithRevData(res http.ResponseWriter, req *http.Request) {
	data := mtr.CTObject{}; //create an empty CTObject
	err := json.NewDecoder(req.Body).Decode(&data); // fill that struct using the JSON encoded struct send via the Post
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid data sent via post: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	newSRD, err := data.DeconstructSRD() //cast the CTObject to a SRD
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid data sent via post: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	newRevData, err := data.DeconstructRevData() //cast the CTObject to a RevData
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid data sent via post: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	err = ca.VerifySRDSignature(newSRD, this.LogID) //verify the signature on the object
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid signature: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	deltaCRV, err := ctca.DecompressCRV(newRevData.CRVDelta) //decompress the delta CRV
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid compression on delta CRV: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}


	if this.CurrentCRVMap == nil { //if this is the first post request made
		this.CurrentCRVMap = make(map[string]map[string] ba.BitArray)
		this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] = ba.NewBitArray((*deltaCRV).Capacity()) // create a new bit array the same size as the deltaCRV
	}

	currentCRV := this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] //get the current CRV, with the current rev type for the requesting ca

	NewCRV := ctca.ApplyCRVDeltaToCRV(&currentCRV, deltaCRV) //apply the delta crv to the crv

	compCRV, err := ctca.CompressCRV(NewCRV) //compress and hash the new CRV to make sure it is consistant
	crvHash, _, err := signature.GenerateHash(tls.SHA256, compCRV)
	if err != nil {
		http.Error(res, fmt.Sprintf("Error Hashing CRV: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	if bytes.Compare(newSRD.RevDigest.CRVHash, crvHash) == 0 { //if delta CRV is consistant
		this.CurrentCRVMap[newSRD.EntityID][newRevData.RevocationType] = *NewCRV //update the curr CRV
	} else {
		http.Error(res, fmt.Sprintf("Inconsistant delta CRV: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
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
		http.Error(res, fmt.Sprintf("Error Updating SRDWithRevData: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	if this.LogSRDWithRevDataMap == nil {
		this.LogSRDWithRevDataMap = make(map[string]map[string] *mtr.SRDWithRevData)
	}
	this.LogSRDWithRevDataMap[newSRD.EntityID][newRevData.RevocationType].RevData.RevocationType = "Let's-Revoke" //update the revocation type
}

func (this *Logger) OnGetLogSRDWithRevData(res http.ResponseWriter, req *http.Request) {
	if this.LogSRDWithRevDataMap == nil { //if the SRDmap hasnt been created yet report that to the caller and return
		res.Write([]byte("SRDWithRevData is still being created"))
		return
	}

	var CTObjects = []mtr.CTObject{} //create an empty slice to hold ctobjects

	for _, element := range this.LogSRDWithRevDataMap {
		LogSRDWithRevData := element["Let's-Revoke"]
		CTObject, err := mtr.ConstructCTObject(LogSRDWithRevData)
		if err != nil {
			http.Error(res, fmt.Sprintf("Error Generating LogSRD objects: %v", err), http.StatusBadRequest) // if there is an eror report and abort
			return;
		}
		CTObjects = append(CTObjects, *CTObject)
	}

	var jsonStr, err = json.Marshal(CTObjects);
	if err == nil {
		res.Write(jsonStr)
	}
}
