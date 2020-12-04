package keyprovider

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containers/ocicrypt/config"
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"io"
	"net"
	"os"
	"testing"
)

//Test runner which mocks binary executable for key wrapping and unwrapping
type TestRunner struct{}

//Mock annotation packet, which goes into container image manifest
type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

//grpc server with mock api implementation for serving the clients with mock WrapKey and Unwrapkey grpc method implementations
type server struct {
	keyproviderpb.UnimplementedKeyProviderServiceServer
}

func init() {
	lis, _ := net.Listen("tcp", ":50051")
	s := grpc.NewServer()
	keyproviderpb.RegisterKeyProviderServiceServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			fmt.Println(err)
		}
	}()
}

// Mock grpc method which returns the wrapped key encapsulated in annotation packet in grpc response for a given key in grpc request
func (*server) WrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	var keyP KeyProviderKeyWrapProtocolInput
	json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	key := []byte("passphrasewhichneedstobe32bytes!")

	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

	jsonString, _ := json.Marshal(annotationPacket{
		KeyUrl:     "https://key-provider/key-uuid",
		WrappedKey: wrappedKey,
		WrapType:   "AES",
	})

	protocolOuputSerialized, _ := json.Marshal(KeyProviderKeyWrapProtocolOuput{
		KeyWrapResults: KeyWrapResults{Annotation: jsonString},
	})

	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil
}

// Mock grpc method which returns the unwrapped key encapsulated in grpc response for a given wrapped key encapsulated in annotation packet in grpc request
func (*server) UnWrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	var keyP KeyProviderKeyWrapProtocolInput
	json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)

	apkt := annotationPacket{}
	json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	key := []byte("passphrasewhichneedstobe32bytes!")
	ciphertext := apkt.WrappedKey

	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	protocolOuputSerialized, _ := json.Marshal(KeyProviderKeyWrapProtocolOuput{
		KeyUnwrapResults: KeyUnwrapResults{OptsData: unwrappedKey},
	})
	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil
}

// Mock Exec Command for wrapping and unwrapping executables
func (r TestRunner) Exec(cmdName string, args []string, input []byte) ([]byte, error) {
	key := []byte("passphrasewhichneedstobe32bytes!")

	if cmdName == "/usr/lib/keyprovider-1-wrapkey" {

		var keyP KeyProviderKeyWrapProtocolInput
		json.Unmarshal(input, &keyP)

		c, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(c)

		nonce := make([]byte, gcm.NonceSize())
		io.ReadFull(rand.Reader, nonce)
		wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

		jsonString, _ := json.Marshal(annotationPacket{
			KeyUrl:     "https://key-provider/key-uuid",
			WrappedKey: wrappedKey,
			WrapType:   "AES",
		})

		return json.Marshal(KeyProviderKeyWrapProtocolOuput{
			KeyWrapResults: KeyWrapResults{
				Annotation: jsonString,
			},
		})
	} else if cmdName == "/usr/lib/keyprovider-1-unwrapkey" {

		var keyP KeyProviderKeyWrapProtocolInput
		json.Unmarshal(input, &keyP)

		apkt := annotationPacket{}
		json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
		ciphertext := apkt.WrappedKey

		c, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(c)
		nonceSize := gcm.NonceSize()
		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		return json.Marshal(KeyProviderKeyWrapProtocolOuput{
			KeyUnwrapResults: KeyUnwrapResults{OptsData: unwrappedKey},
		})
	}
	return nil, errors.New("unkown protocol")
}

func TestKeyWrapKeyProviderCommandSuccess(t *testing.T) {
	testConfigFile := "config.json"
	os.Setenv("OCICRYPT_KEYPROVIDER_CONFIG", testConfigFile)
	//Config File with executable for key wrap
	configFile1 := `{"key-providers": {
                "keyprovider-1": {
                   "cmd": "/usr/lib/keyprovider-1-wrapkey",
                   "args": []
                }
        }}
        `
	//Config File with executable for key unwrap
	configFile2 := `{"key-providers": {
                "keyprovider-1": {
                   "cmd": "/usr/lib/keyprovider-1-unwrapkey",
                   "args": []
                }
        }}
        `
	configFile, _ := os.OpenFile(testConfigFile, os.O_CREATE|os.O_WRONLY, 0644)
	configFile.Write([]byte(configFile1))
	configFile.Close()

	optsData := []byte("data to be encrypted")

	kewrapper := NewKeyWrapper()

	parameters := make(map[string][][]byte)
	parameters["keyprovider-1"] = nil
	ec := config.EncryptConfig{
		Parameters:    parameters,
		DecryptConfig: config.DecryptConfig{},
	}
	runner = TestRunner{}
	keyWrapOutput, err := kewrapper.WrapKeys(&ec, optsData)
	assert.NoError(t, err)

	configFile, _ = os.OpenFile(testConfigFile, os.O_CREATE|os.O_WRONLY, 0644)
	configFile.Write([]byte(configFile2))
	configFile.Close()

	dc := config.DecryptConfig{
		Parameters: nil,
	}
	keyUnWrapOutput, err := kewrapper.UnwrapKey(&dc, keyWrapOutput)
	assert.NoError(t, err)
	assert.Equal(t, optsData, keyUnWrapOutput)
	os.Remove(testConfigFile)
}

func TestKeyWrapKeyProviderGRPCSuccess(t *testing.T) {
	path := "config.json"
	os.Setenv("OCICRYPT_KEYPROVIDER_CONFIG", path)
	filecontent := `{"key-providers": {
                "keyprovider-1": {
                   "grpc": "localhost:50051"
                },
		"keyprovider-2": {
                   "grpc": "localhost:3990"
                },
                "keyprovider-3": {
                   "cmd": "/usr/lib/unwrapkey",
                   "args": []
                }

        }}
        `
	tempFile, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	tempFile.Write([]byte(filecontent))
	tempFile.Close()

	optsData := []byte("data to be encrypted")

	kewrapper := NewKeyWrapper()

	parameters := make(map[string][][]byte)
	parameters["keyprovider-1"] = nil
	ec := config.EncryptConfig{
		Parameters:    parameters,
		DecryptConfig: config.DecryptConfig{},
	}

	runner = TestRunner{}
	keyWrapOutput, err := kewrapper.WrapKeys(&ec, optsData)
	assert.NoError(t, err)

	dc := config.DecryptConfig{
		Parameters: nil,
	}
	keyUnWrapOutput, err := kewrapper.UnwrapKey(&dc, keyWrapOutput)
	assert.NoError(t, err)
	assert.Equal(t, optsData, keyUnWrapOutput)

	os.Remove(path)
}
