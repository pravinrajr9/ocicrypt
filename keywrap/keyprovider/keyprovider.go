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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containers/ocicrypt/config"
	keyprovider_config "github.com/containers/ocicrypt/config/keyprovider-config"
	"github.com/containers/ocicrypt/keywrap"
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	"time"
	"net"
	"google.golang.org/grpc"
	"os/exec"
	"strings"
	"sync"
)

type keyProviderKeyWrapper struct {
}

var rpcMutex sync.Mutex
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
	CommandName string `json:"cmd"`
	Args []string `json:"args"`
}

type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

// WrapKeys wraps the session key for recipients and encrypts the optsData, which
// describe the symmetric key used for encrypting the layer
func (kw *keyProviderKeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {
	ic, err := keyprovider_config.GetConfiguration()
	if err != nil{
		return nil, err
	}

	input, _ := json.Marshal(KeyProviderKeyWrapProtocolInput{
		Operation:       OpKeyWrap,
		KeyWrapParams:   KeyWrapParams{
			Ec:       ec,
			OptsData: optsData,
		},
	})
	var outPut KeyProviderKeyWrapProtocolOuput
	fmt.Println(ec.Parameters)
	fmt.Println(ic.KeyProviderConfig)
	for providers, args := range ic.KeyProviderConfig{
		if _, ok := ec.Parameters[providers]; ok{
			providersMap := args.(map[string]interface{})
			if _, ok := providersMap["cmd"]; ok{
				fmt.Println(args)
				c := command{}
				jsonString, _ := json.Marshal(providersMap)
				json.Unmarshal(jsonString, &c)
				cmd := exec.Command(c.CommandName, strings.Join(c.Args, " "))
				fmt.Println(c.CommandName)

				stdInputBuffer := bytes.NewBuffer(input)
				cmd.Stdin = stdInputBuffer
				var out bytes.Buffer
				cmd.Stdout = &out
				err := cmd.Run()
				if err != nil {
					return nil, errors.New("Error running command " +err.Error())
				}
				err = json.Unmarshal(out.Bytes(), &outPut)
				ap := annotationPacket{}
				fmt.Println(err)
                                err = json.Unmarshal(outPut.KeyWrapResults.Annotation, &ap)
                                fmt.Println(string(outPut.KeyWrapResults.Annotation))

				return outPut.KeyWrapResults.Annotation, nil
			} else if socketFile, ok := providersMap["grpc"]; ok{
				socketFileStr := socketFile.(string)
				fmt.Println(socketFileStr)
				cc, err := grpc.Dial(socketFileStr, grpc.WithInsecure())
				defer cc.Close()
				if err != nil {
					return nil, errors.New("Error while dialing rpc server: "+ err.Error())
				}
				client := keyproviderpb.NewKeyProviderServiceClient(cc)
				req := &keyproviderpb.KeyProviderKeyWrapProtocolInput{
					KeyProviderKeyWrapProtocolInput: input,
				}

				resp, _ := client.WrapKey(context.Background(), req)
				respBytes := resp.GetKeyProviderKeyWrapProtocolOutput()
				fmt.Println(string(respBytes))
				err = json.Unmarshal(respBytes, &outPut)
				if err != nil {
					return nil, errors.New("Error while unmarshalling: "+ err.Error())
				}
                                ap := annotationPacket{}
                                fmt.Println(err)
                                err = json.Unmarshal(outPut.KeyWrapResults.Annotation, &ap)
                                fmt.Println(string(outPut.KeyWrapResults.Annotation))

				return outPut.KeyWrapResults.Annotation, nil
			} else {
				return nil, errors.New("Unsupported protocol")
			}
		}
	}
	return nil, nil
}

// Dialer function used as a parameter for 'grpc.WithDialer'
func dialer(socket, address string, timeoutVal time.Duration) func(string, time.Duration) (net.Conn, error) {
    return func(addr string, timeout time.Duration) (net.Conn, error) {
        addr, timeout = address, timeoutVal
        return net.DialTimeout(socket, addr, timeoutVal)
    }
}

func (kw *keyProviderKeyWrapper) UnwrapKey(dc *config.DecryptConfig, jsonString []byte) ([]byte, error) {
	fmt.Println("UnwrapKey UnwrapKey")
	//rpcMutex.Lock()
	//defer rpcMutex.Unlock()
	ic, err := keyprovider_config.GetConfiguration()
	if err != nil{
		return nil, err
	}

	input, err := json.Marshal(KeyProviderKeyWrapProtocolInput{
		Operation:       OpKeyWrap,
		KeyUnwrapParams: KeyUnwrapParams{
			Dc:        dc,
			Annotation: jsonString,
		},
	})
	fmt.Println(err)
	var outPut KeyProviderKeyWrapProtocolOuput

	for _, args := range ic.KeyProviderConfig{
			providersMap := args.(map[string]interface{})
			if cmd, ok := providersMap["cmd"]; ok{
				c := command{}
				jsonString, _ := json.Marshal(cmd)
				json.Unmarshal(jsonString, &c)
				cmd := exec.Command(c.CommandName, strings.Join(c.Args, " "))


				stdInputBuffer := bytes.NewBuffer(input)
				cmd.Stdin = stdInputBuffer
				var out bytes.Buffer
				cmd.Stdout = &out
				err := cmd.Run()
				if err != nil {
					return nil, errors.New("Error running command " +err.Error())
				}

				json.Unmarshal(out.Bytes(), &outPut)
				return outPut.KeyUnwrapResults.OptsData, nil
			} else if socketFile, ok := providersMap["grpc"]; ok{
				socketFileStr := socketFile.(string)
				 fmt.Println(socketFileStr)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second )
				defer cancel()
				cc, err := grpc.Dial(socketFileStr, grpc.WithInsecure())
				defer cc.Close()
				if err != nil {
					return nil, errors.New("Error while dialing rpc server: "+ err.Error())
				}
				fmt.Println(err)
				client := keyproviderpb.NewKeyProviderServiceClient(cc)
				req := &keyproviderpb.KeyProviderKeyWrapProtocolInput{
					KeyProviderKeyWrapProtocolInput: input,
				}

				resp, err := client.UnWrapKey(ctx, req)
				//fmt.Println(err.Error())
				respBytes := resp.GetKeyProviderKeyWrapProtocolOutput()
				fmt.Println(string(respBytes))
				err = json.Unmarshal(respBytes, &outPut)
				
				if err != nil {
					return nil, errors.New("Error while unmarshalling: "+ err.Error())
				}
				return outPut.KeyUnwrapResults.OptsData, nil
			} else {
				return nil, errors.New("Unsupported protocol")
			}
	}
	return nil, nil
}

// Not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) NoPossibleKeys(dcparameters map[string][][]byte) bool {
	return false
}

// Not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) GetPrivateKeys(dcparameters map[string][][]byte) [][]byte {
	return nil
}

// Not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) GetKeyIdsFromPacket(_ string) ([]uint64, error) {
	return nil, nil
}

// Not applicable to keyprovider protocol
func (kw *keyProviderKeyWrapper) GetRecipients(_ string) ([]string, error) {
	return nil, nil
}
