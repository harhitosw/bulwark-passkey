package main

import (
	"bytes"
	"encoding/json"
	//"encoding/hex"
	"encoding/base64"
	"time"
     "crypto/x509"
	"github.com/bulwarkid/virtual-fido/identities"
)

type Client struct {
	vaultType      string
	email          string
	lastUpdated    time.Time
	deletedSources [][]byte
	fidoClient     *FIDOClient
}

func newClient() *Client {
	client := &Client{
		deletedSources: make([][]byte, 0),
	}
	client.fidoClient = newFIDOClient(client)
	return client
}

func (client *Client) deleteIdentity(id []byte) bool {
	success := client.fidoClient.vault.DeleteIdentity(id)
	if success {
		client.FIDOUpdated()
	}
	return success
}

func (client *Client) identities() []*identities.CredentialSource {
	return client.fidoClient.vault.CredentialSources
}

func (client *Client) passphrase() string {
	passphrase := getPassphrase()
	assert(passphrase != "", "Passphrase cannot be empty")
	return passphrase
}

func (client *Client) passphraseChanged() {
	client.lastUpdated = now()
	client.save()
}

func (client *Client) configureNewDevice(vaultType string) {
	client.fidoClient.configureNewClient()
	client.vaultType = vaultType
	client.lastUpdated = now()
	client.save()
}

func (client *Client) loadData(vaultType string, data []byte, lastUpdated string, email string) {
	// Check if data receives is in the old format
	// TODO (Chris): Remove this by perhaps 6/2023, assuming nobody is using the old version
	testState, err := identities.DecryptFIDOState(data, client.passphrase())
	if err == nil && testState.EncryptionKey != nil {
		client.deprecatedLoadData(vaultType, data, lastUpdated, email)
		return
	}
	savedState, err := decryptSavedState(data, client.passphrase())
	checkErr(err, "Could not load saved state data")
	config, err := identities.DecryptFIDOState(savedState.VirtualFIDOConfig, client.passphrase())
	debugf("Decrypted and unmarshalled data from : %+v",config)
	checkErr(err, "Could not decrypt saved FIDO state")
	// log the private key and all the other credentials stored in the safe file on the local machine 
	credPrivateKeyArray := config.Sources[0].PrivateKey
	credIDByteArray := config.Sources[0].ID
	// convert Credential ID Byte array to base64 format
	base64StringID:=base64.StdEncoding.EncodeToString(credIDByteArray)
	debugf("Base 64 of the Crrd ID: %+v",base64StringID)
	debugf("Cred Private key array%+v",credPrivateKeyArray)
	base64StringCredPrivateKeyArray:= base64.StdEncoding.EncodeToString(credPrivateKeyArray)
	debugf("Base 64 of the Cred Private Key array : %+v",base64StringCredPrivateKeyArray)
	//parse the EC private key to get the PrivateKey format of the Byte array
	credPrivateKey,credErr := x509.ParseECPrivateKey(credPrivateKeyArray)
    checkErr(credErr, "Could get the credential private key !!!!")
	//convert that private key to PKCS8 format array 
	getPKCSArray,errPKCS := x509.MarshalPKCS8PrivateKey(credPrivateKey)
	checkErr(errPKCS, "Could get the credential private key PKCS array !!!!")
	debugf("PKCS Array in format : %+v",getPKCSArray)
	//encode PKCS8 format array to base64 string which is now portable to any use-case
	base64String:= base64.StdEncoding.EncodeToString(getPKCSArray)
	debugf("Base 64 of the PKCS array : %+v",base64String)
	lastUpdatedTime := now()
	err = (&lastUpdatedTime).UnmarshalText([]byte(lastUpdated))
	checkErr(err, "Could not parse time")
	client.vaultType = vaultType
	client.email = email
	client.lastUpdated = lastUpdatedTime
	client.fidoClient.loadConfig(config)
    b,err1:=x509.MarshalECPrivateKey(client.fidoClient.certPrivateKey)
	checkErr(err1,"Some error here")
	//str:=hex.EncodeToString(b)
	publickey1,err2:= client.fidoClient.certPrivateKey.PublicKey.ECDH()
	checkErr(err2,"Some error here")
	publickeyBytes:=publickey1.Bytes()
	//str1:=hex.EncodeToString(publickeyBytes)
	debugf("Public Key Byte Array:%+v",publickeyBytes)
	
	debugf("Marshal private key byte array:%+v",b)
	debugf("client.fidoClient.certPrivateKey:%+v",client.fidoClient.certPrivateKey)
	
	debugf("client.fidoClient.certPrivateKey.publickey:%+v",client.fidoClient.certPrivateKey.PublicKey)
	

	message := "Here to save"
	debugf("The state: %s",message)
	client.save()
}



func (client *Client) updateData(data []byte, lastUpdated string) {
	// Check if the data received is the old version
	// TODO (Chris): remove this after a few months, perhaps 06/2023?
	// Will have to check if anybody is using the old version of the app
	testState, err := identities.DecryptFIDOState(data, client.passphrase())
	if err == nil && testState.EncryptionKey != nil {
		client.deprecatedUpdateData(data, lastUpdated)
		return
	}
	savedStateBytes, err := identities.DecryptWithPassphrase(client.passphrase(), data)
	if err != nil {
		errorf("Invalid state data provided: %w", err)
		return
	}
	savedState := ClientSavedState{}
	err = json.Unmarshal(savedStateBytes, &savedState)
	if err != nil {
		errorf("Invalid state json data provided: %w", err)
		return
	}
	config, err := identities.DecryptFIDOState(savedState.VirtualFIDOConfig, client.passphrase())
	if err != nil {
		errorf("Invalid FIDO state in data: %w", err)
		return
	}
	lastUpdatedTime := now()
	err = (&lastUpdatedTime).UnmarshalText([]byte(lastUpdated))
	checkErr(err, "Could not parse time")
	client.lastUpdated = lastUpdatedTime
	for _, sourceId := range savedState.DeletedSources {
		if !containsArray(sourceId, client.deletedSources) {
			client.deletedSources = append(client.deletedSources, sourceId)
		}
	}
	// Merge old and new sources, avoiding deleted and existing ones
	newSources := make([]identities.SavedCredentialSource, 0)
	addSources := func(sources []identities.SavedCredentialSource) {
		for _, source := range sources {
			shouldAdd := !containsArray(source.ID, client.deletedSources)
			if !shouldAdd {
				continue
			}
			for _, existing := range newSources {
				if bytes.Equal(source.ID, existing.ID) {
					shouldAdd = false
					break
				}
			}
			if shouldAdd {
				newSources = append(newSources, source)
			}
		}
	}
	addSources(client.fidoClient.vault.Export())
	addSources(config.Sources)
	config.Sources = newSources
	client.fidoClient.loadConfig(config)
}

func (client *Client) FIDOUpdated() {
	client.lastUpdated = now()
	client.save()
}

type ClientSavedState struct {
	VirtualFIDOConfig []byte
	DeletedSources    [][]byte
}

func decryptSavedState(data []byte, passphrase string) (*ClientSavedState, error) {
	savedStateBytes, err := identities.DecryptWithPassphrase(passphrase, data)
	if err != nil {
		return nil, err
	}
	savedState := ClientSavedState{}
	//debugf("Decrypted and unmarshalled data is: %+v",savedState)
	err = json.Unmarshal(savedStateBytes, &savedState)
	if err != nil {
		return nil, err
	}
	
	return &savedState, nil
}

func (client *Client) exportSavedState() []byte {
	config := client.fidoClient.exportConfig()
	encryptedConfig, err := identities.EncryptFIDOState(*config, client.passphrase())
	state := ClientSavedState{
		VirtualFIDOConfig: encryptedConfig,
		DeletedSources:    client.deletedSources,
	}
	stateBytes, err := json.Marshal(state)
	checkErr(err, "Could not marshal JSON")
	encryptedState, err := identities.EncryptWithPassphrase(client.passphrase(), stateBytes)
	checkErr(err, "Could not encrypt state")
	return encryptedState
}

func (client *Client) save() {
	config := client.exportSavedState()
	vaultFile := VaultFile{VaultType: client.vaultType, Email: client.email, Data: config, LastUpdated: toTimestamp(client.lastUpdated)}
	favicons, err := exportFaviconCache()
	if err == nil {
		vaultFile.Favicons = favicons
	}
	saveVaultToFile(vaultFile)
	updateFrontend()
	storeRemoteVaultJSON(string(config), toTimestamp(client.lastUpdated))
}

// --------------------------
// Deprecated Methods
// --------------------------

func (client *Client) deprecatedLoadData(vaultType string, data []byte, lastUpdated string, email string) {
	lastUpdatedTime := now()
	err := (&lastUpdatedTime).UnmarshalText([]byte(lastUpdated))
	checkErr(err, "Could not parse time")
	config, err := identities.DecryptFIDOState(data, client.passphrase())
	checkErr(err, "Could not decrypt vault file")
	client.vaultType = vaultType
	client.email = email
	client.lastUpdated = lastUpdatedTime
	client.fidoClient.loadConfig(config)
	client.save()
}

func (client *Client) deprecatedUpdateData(data []byte, lastUpdated string) {
	newLastUpdated := parseTimestamp(lastUpdated)
	if !client.lastUpdated.Before(*newLastUpdated) {
		return
	}
	_, err := identities.DecryptFIDOState(data, client.passphrase())
	if err != nil {
		// Passphrase might have changed, get user to log in again
		eject := logIn(accountVaultType, string(data), client.email)
		if eject {
			deleteVaultFile()
			app.createNewVault()
		} else {
			_, err = identities.DecryptFIDOState(data, client.passphrase())
			checkErr(err, "Could not decrypt new vault")
		}
	}
	client.deprecatedLoadData(accountVaultType, data, lastUpdated, client.email)
}
