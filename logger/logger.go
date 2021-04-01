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

//type to hold data and functionality of a Relying Party
type Logger struct {
	LogSRDWithRevData	*mtr.SRDWithRevData
	CurrentCRV			ba.BitArray
	Port 				string
	Address				string
	LogID				string
	Signer 				*signature.Signer
}

type LoggerConfig struct {
	LogID	string `json:"LogID"`
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

	signer,err := signature.NewSigner("privatekey?")
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
	newSRVWithRevData, err := deconstructSRDWithRevData(&data) //cast the CTObject to a SRVWithRevData
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid data sent via post: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	err = ca.VerifySRDSignature(&newSRVWithRevData.SRD, this.LogID) //verify the signature on the object
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid signature: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	deltaCRV, err := ctca.DecompressCRV(newSRVWithRevData.RevData.CRVDelta) //decompress the delta CRV
	if err != nil {
		http.Error(res, fmt.Sprintf("Invalid compression on delta CRV: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	if this.CurrentCRV == nil { //if this is the first post request made
		this.CurrentCRV = ba.NewBitArray((*deltaCRV).Capacity()) // create a new bit array the same size as the deltaCRV
	}

	NewCRV := ctca.ApplyCRVDeltaToCRV(&this.CurrentCRV, deltaCRV) //apply the delta crv to the crv

	compCRV, err := ctca.CompressCRV(NewCRV) //compress and hash the new CRV to make sure it is consistant
	crvHash, _, err := signature.GenerateHash(tls.SHA256, compCRV)
	if err != nil {
		http.Error(res, fmt.Sprintf("Error Hashing CRV: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}

	if bytes.Compare(newSRVWithRevData.SRD.RevDigest.CRVHash, crvHash) == 0 { //if delta CRV is consistant
		this.CurrentCRV = *NewCRV //update the curr CRV
	} else {
		http.Error(res, fmt.Sprintf("Inconsistant delta CRV: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
	//update the SRDWithRevData
	this.LogSRDWithRevData, err = ca.CreateSRDWithRevData(
		&this.CurrentCRV, deltaCRV,
		newSRVWithRevData.SRD.RevDigest.Timestamp,
		this.LogID,
		tls.SHA256,
		this.Signer,
	)

	if err != nil {
		http.Error(res, fmt.Sprintf("Error Updating SRDWithRevData: %v", err), http.StatusBadRequest) // if there is an eror report and abort
		return;
	}
}

func (this *Logger) OnGetLogSRDWithRevData(res http.ResponseWriter, req *http.Request) {
	CTObject, err := mtr.ConstructCTObject(this.LogSRDWithRevData)
	if err == nil {
		var jsonStr, err = json.Marshal(CTObject);
		if err == nil {
			res.Write(jsonStr)
		}
	}
}

func deconstructSRDWithRevData(c *mtr.CTObject) (*mtr.SRDWithRevData, error) {
	var srd_rev mtr.SRDWithRevData
	err := json.Unmarshal(c.Blob, &srd_rev)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing SRDWithRevData from %s CTObject: %v", c.TypeID, err)
	}
	return &srd_rev, nil
}
