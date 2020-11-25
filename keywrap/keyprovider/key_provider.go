/*
   Copyright The ocicrypt Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package keyprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/containers/ocicrypt/config"
	keyprovider_config "github.com/containers/ocicrypt/config/keyprovider-config"
	"github.com/containers/ocicrypt/keywrap"
	"os/exec"
	"strings"
)

type keyProviderKeyWrapper struct {
}

func (kw *keyProviderKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.experimental.keyprovider"
}

// NewKeyWrapper returns a new key wrapping interface using key-provider
func NewKeyWrapper() keywrap.KeyWrapper {
	return &keyProviderKeyWrapper{}
}

type KeyProviderKeyWrapProtocolOperation string

var (
	OpKeyWrap KeyProviderKeyWrapProtocolOperation = "keywrap"
	OpKeyUnwrap KeyProviderKeyWrapProtocolOperation = "keyunwrap"
)

type KeyProviderKeyWrapProtocolInput struct {
	// Operation is either "keywrap" or "keyunwrap"
	Operation KeyProviderKeyWrapProtocolOperation `json:"op"`
	// KeyWrapParams encodes the arguments to key wrap if operation is set to wrap
	KeyWrapParams KeyWrapParams `json:"keywrapparams",omitempty`
	// KeyUnwrapParams encodes the arguments to key unwrap if operation is set to unwrap
	KeyUnwrapParams KeyUnwrapParams `json:"keyunwrapparams",omitempty`
}


type KeyProviderKeyWrapProtocolOuput struct {
	// KeyWrapResult encodes the results to key wrap if operation is to wrap
	KeyWrapResults  KeyWrapResults `json:"keywrapresults",omitempty`
	// KeyUnwrapResult encodes the result to key unwrap if operation is to unwrap
	KeyUnwrapResults KeyUnwrapResults `json:"keyunwrapresults",omitempty`
}

type KeyWrapParams struct {
	Ec *config.EncryptConfig `json:"ec"`
	OptsData []byte `json:"optsdata"`
}
type KeyUnwrapParams struct {
	Dc *config.DecryptConfig `json:"dc"`
	Annotation []byte `json:"annotation"`
}

type KeyUnwrapResults struct {
	OptsData []byte `json:"optsdata"`
}
type KeyWrapResults struct {
	Annotation[]byte `json:"annotation"`
}

type command struct {
	commandName string `json:"cmd"`
	args []string `json:"args"`
}

// WrapKeys wraps the session key for recipients and encrypts the optsData, which
// describe the symmetric key used for encrypting the layer
func (kw *keyProviderKeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {
	ic, err := keyprovider_config.GetConfiguration()
	if err != nil{
		return nil, err
	}
	for providers, args := range ic.KeyProviderConfig{
		if _, ok := ec.Parameters[providers]; ok{
			providersMap := args.(map[string]interface{})
			if cmd, ok := providersMap["cmd"]; ok{
				c := command{}
				jsonString, _ := json.Marshal(cmd)
				json.Unmarshal(jsonString, &c)
				cmd := exec.Command(c.commandName, strings.Join(c.args, " "))

				stdInput, _ := json.Marshal(KeyProviderKeyWrapProtocolInput{
					Operation:   OpKeyWrap    ,
					KeyWrapParams:   KeyWrapParams{},
				})
				stdInputBuffer := bytes.NewBuffer(stdInput)
				cmd.Stdin = stdInputBuffer
				var out bytes.Buffer
				cmd.Stdout = &out
				err := cmd.Run()
				if err != nil {
					return nil, errors.New("Error running command " +err.Error())
				}
				var outPut KeyProviderKeyWrapProtocolOuput
				json.Unmarshal(out.Bytes(), &outPut)
			} else if _, ok := providersMap["grpc"]; ok{
				return nil, nil
			} else {
				return nil, errors.New("Unsupported protocal")
			}
		}
	}
	return nil, nil
}

func (kw *keyProviderKeyWrapper) UnwrapKey(dc *config.DecryptConfig, jsonString []byte) ([]byte, error) {
	return nil, nil
}

func (kw *keyProviderKeyWrapper) NoPossibleKeys(dcparameters map[string][][]byte) bool {
	return true
}

func (kw *keyProviderKeyWrapper) GetPrivateKeys(dcparameters map[string][][]byte) [][]byte {
	return nil
}

func (kw *keyProviderKeyWrapper) GetKeyIdsFromPacket(_ string) ([]uint64, error) {
	return nil, nil
}

func (kw *keyProviderKeyWrapper) GetRecipients(_ string) ([]string, error) {
	return nil, nil
}
