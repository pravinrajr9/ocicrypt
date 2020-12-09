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
	"context"
	"encoding/json"
	"github.com/containers/ocicrypt/config"
	"github.com/containers/ocicrypt/keywrap"
	"github.com/containers/ocicrypt/utils"
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type keyProviderKeyWrapper struct {
	provider string
	args     interface{}
}

func (kw *keyProviderKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.provider." + kw.provider
}

// NewKeyWrapper returns a new key wrapping interface using keyprovider
func NewKeyWrapper(p string, a interface{}) keywrap.KeyWrapper {
	return &keyProviderKeyWrapper{provider: p, args: a}
}

type KeyProviderKeyWrapProtocolOperation string

var (
	OpKeyWrap   KeyProviderKeyWrapProtocolOperation = "keywrap"
	OpKeyUnwrap KeyProviderKeyWrapProtocolOperation = "keyunwrap"
)

type KeyProviderKeyWrapProtocolInput struct {
	// Operation is either "keywrap" or "keyunwrap"
	Operation KeyProviderKeyWrapProtocolOperation `json:"op"`
	// KeyWrapParams encodes the arguments to key wrap if operation is set to wrap
	KeyWrapParams KeyWrapParams `json:"keywrapparams, omitempty"`
	// KeyUnwrapParams encodes the arguments to key unwrap if operation is set to unwrap
	KeyUnwrapParams KeyUnwrapParams `json:"keyunwrapparams, omitempty"`
}

type KeyProviderKeyWrapProtocolOuput struct {
	// KeyWrapResult encodes the results to key wrap if operation is to wrap
	KeyWrapResults KeyWrapResults `json:"keywrapresults, omitempty"`
	// KeyUnwrapResult encodes the result to key unwrap if operation is to unwrap
	KeyUnwrapResults KeyUnwrapResults `json:"keyunwrapresults, omitempty"`
}

type KeyWrapParams struct {
	Ec       *config.EncryptConfig `json:"ec"`
	OptsData []byte                `json:"optsdata"`
}

type KeyUnwrapParams struct {
	Dc         *config.DecryptConfig `json:"dc"`
	Annotation []byte                `json:"annotation"`
}

type KeyUnwrapResults struct {
	OptsData []byte `json:"optsdata"`
}

type KeyWrapResults struct {
	Annotation []byte `json:"annotation"`
}

type command struct {
	CommandName string   `json:"cmd"`
	Args        []string `json:"args, omitempty"`
}

var runner utils.CommandExecuter

func init() {
	runner = utils.Runner{}
}

// WrapKeys wraps reads out the OCICRYPT_KEYPROVIDER_CONFIG env variable and calls appropriate binary executable/grpc server for wrapping the session key for recipients and gets encrypted optsData, which
// describe the symmetric key used for encrypting the layer
func (kw *keyProviderKeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {

	input, err := json.Marshal(KeyProviderKeyWrapProtocolInput{
		Operation: OpKeyWrap,
		KeyWrapParams: KeyWrapParams{
			Ec:       ec,
			OptsData: optsData,
		},
	})

	if err != nil {
		return nil, err
	}

	// Iterate over the ec.Parameters and execute appropriate binaries or dial a grpc based on protocol mentioned in encryption config
	for provider, _ := range ec.Parameters {
		if kw.provider == provider {
			providersMap := kw.args.(map[string]interface{})
			if _, ok := providersMap["cmd"]; ok {
				protocolOuput, err := GetProviderCommandOutput(input, providersMap)
				if err != nil {
					return nil, errors.Wrap(err, "error while retrieving keyprovider protocol command output")
				}
				return protocolOuput.KeyWrapResults.Annotation, nil
			} else if socketFile, ok := providersMap["grpc"]; ok {
				protocolOuput, err := GetProviderGRPCOutput(input, socketFile, OpKeyWrap)
				if err != nil {
					return nil, errors.Wrap(err, "error while retrieving keyprovider protocol grpc output")
				}

				return protocolOuput.KeyWrapResults.Annotation, nil
			} else {
				return nil, errors.New("unsupported keyprovider invocation. supported invocation methods are grpc and cmd")
			}
		}
	}

	return nil, nil
}

// UnwrapKey wraps reads out the OCICRYPT_KEYPROVIDER_CONFIG env variable and calls appropriate binary executable/grpc server for unwrapping the session key based on the protocol given in annotation for recipients and gets decrypted optsData,
// which describe the symmetric key used for decrypting the layer
func (kw *keyProviderKeyWrapper) UnwrapKey(dc *config.DecryptConfig, jsonString []byte) ([]byte, error) {

	input, err := json.Marshal(KeyProviderKeyWrapProtocolInput{
		Operation: OpKeyWrap,
		KeyUnwrapParams: KeyUnwrapParams{
			Dc:         dc,
			Annotation: jsonString,
		},
	})
	if err != nil {
		return nil, err
	}

	providersMap := kw.args.(map[string]interface{})
	if _, ok := providersMap["cmd"]; ok {
		protocolOuput, err := GetProviderCommandOutput(input, providersMap)
		if err != nil {
			// If err is not nil, then ignore it and continue with rest of the given keyproviders
			return nil, err
		}

		return protocolOuput.KeyUnwrapResults.OptsData, nil
	} else if socketFile, ok := providersMap["grpc"]; ok {
		protocolOuput, err := GetProviderGRPCOutput(input, socketFile, OpKeyUnwrap)
		if err != nil {
			// If err is not nil, then ignore it and continue with rest of the given keyproviders
			return nil, err
		}

		return protocolOuput.KeyUnwrapResults.OptsData, nil
	} else {
		return nil, errors.New("unsupported keyprovider invocation. supported invocation methods are grpc and cmd ")
	}

	return nil, nil
}

func GetProviderGRPCOutput(input []byte, socketFile interface{}, operation KeyProviderKeyWrapProtocolOperation) (*KeyProviderKeyWrapProtocolOuput, error) {
	socketFileStr := socketFile.(string)
	var protocolOuput KeyProviderKeyWrapProtocolOuput
	var grpcOutput *keyproviderpb.KeyProviderKeyWrapProtocolOutput
	cc, err := grpc.Dial(socketFileStr, grpc.WithInsecure())
	defer cc.Close()
	if err != nil {
		return nil, errors.Wrap(err, "error while dialing rpc server")
	}

	client := keyproviderpb.NewKeyProviderServiceClient(cc)
	req := &keyproviderpb.KeyProviderKeyWrapProtocolInput{
		KeyProviderKeyWrapProtocolInput: input,
	}

	if operation == OpKeyWrap {
		grpcOutput, err = client.WrapKey(context.Background(), req)
		if err != nil {
			return nil, errors.Wrap(err, "Error from grpc method")
		}
	} else if operation == OpKeyUnwrap {
		grpcOutput, err = client.UnWrapKey(context.Background(), req)
		if err != nil {
			return nil, errors.Wrap(err, "Error from grpc method")
		}
	}

	respBytes := grpcOutput.GetKeyProviderKeyWrapProtocolOutput()
	err = json.Unmarshal(respBytes, &protocolOuput)
	if err != nil {
		return nil, errors.Wrap(err, "Error while unmarshalling grpc method output")
	}

	return &protocolOuput, nil
}

func GetProviderCommandOutput(input []byte, providersMap map[string]interface{}) (*KeyProviderKeyWrapProtocolOuput, error) {

	var protocolOuput KeyProviderKeyWrapProtocolOuput
	// Convert interface to command structure
	c := command{}
	jsonString, err := json.Marshal(providersMap)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonString, &c)
	if err != nil {
		return nil, err
	}
	respBytes, err := runner.Exec(c.CommandName, c.Args, input)
	err = json.Unmarshal(respBytes, &protocolOuput)

	if err != nil {
		return nil, errors.Wrap(err, "Error while unmarshalling binary executable command output")
	}
	return &protocolOuput, nil
}

// Return false as it is not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) NoPossibleKeys(dcparameters map[string][][]byte) bool {
	return false
}

// Return nil as it is not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) GetPrivateKeys(dcparameters map[string][][]byte) [][]byte {
	return nil
}

// Return nil as it is not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) GetKeyIdsFromPacket(_ string) ([]uint64, error) {
	return nil, nil
}

// Return nil as it is not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) GetRecipients(_ string) ([]string, error) {
	return nil, nil
}
