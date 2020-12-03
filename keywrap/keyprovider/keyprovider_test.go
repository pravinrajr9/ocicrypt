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
	//"google.golang.org/grpc/test/bufconn"
	"io"
	"log"
	"os"
	"testing"
	"net"
)

type TestRunner struct{}

type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

type server struct {
	keyproviderpb.UnimplementedKeyProviderServiceServer
}

func (*server) UnWrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	fmt.Println("Server UnWrapKey")

	var keyP KeyProviderKeyWrapProtocolInput
	json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	fmt.Println(string(keyP.KeyUnwrapParams.Annotation))

	apkt := annotationPacket{}
	err := json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	fmt.Println(err)
	key := []byte("passphrasewhichneedstobe32bytes!")
	ciphertext := apkt.WrappedKey

	c, err := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(c)

	nonceSize := gcm.NonceSize()

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	fmt.Println(string(unwrappedKey))

	a := KeyProviderKeyWrapProtocolOuput{
		KeyUnwrapResults:   KeyUnwrapResults{ OptsData: unwrappedKey},
	}
	b, err := json.Marshal(a)
	fmt.Println(err)
	k := keyproviderpb.KeyProviderKeyWrapProtocolOutput{}
	k.KeyProviderKeyWrapProtocolOutput = b
	return &k, nil
}

func (*server) WrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	fmt.Println("Server WrapKey")

	var keyP KeyProviderKeyWrapProtocolInput
	json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	key := []byte("passphrasewhichneedstobe32bytes!")

	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)

        nonce := make([]byte, gcm.NonceSize())
        if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
              fmt.Println(err)
        }
        wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)
        ap := annotationPacket{
              KeyUrl:     "https://key-provider/key-uuid",
              WrappedKey: wrappedKey,
              WrapType:   "AES",
        }
       jsonString, _ := json.Marshal(ap)

	protocolOuput := KeyProviderKeyWrapProtocolOuput{
		KeyWrapResults: KeyWrapResults{Annotation: jsonString},
	}
	protocolOuputSerialized, _ := json.Marshal(protocolOuput)
	k := keyproviderpb.KeyProviderKeyWrapProtocolOutput{}
	k.KeyProviderKeyWrapProtocolOutput = protocolOuputSerialized
	return &k, nil
}


func (r TestRunner) Exec(cmdName string, args []string, input []byte) ([]byte, error) {
	if cmdName == "/usr/lib/keyprovider-1-wrapkey" {
		fmt.Println("wrap")
		key := []byte("passphrasewhichneedstobe32bytes!")

	        var keyP KeyProviderKeyWrapProtocolInput
	        json.Unmarshal(input, &keyP)

		c, _ := aes.NewCipher(key)
		gcm, err := cipher.NewGCM(c)

		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			fmt.Println(err)
		}
		wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)
		ap := annotationPacket{
			KeyUrl:     "https://key-provider/key-uuid",
			WrappedKey: wrappedKey,
			WrapType:   "AES",
		}

		jsonString, _ := json.Marshal(ap)

		protocolOuput := KeyProviderKeyWrapProtocolOuput{
			KeyWrapResults: KeyWrapResults{
				Annotation: jsonString,
			},
		}
		protocolOuputSerialized, _ := json.Marshal(protocolOuput)
		return protocolOuputSerialized, nil
	} else if cmdName == "/usr/lib/keyprovider-1-unwrapkey" {
		fmt.Println("unwrap")
		var keyP KeyProviderKeyWrapProtocolInput
		err := json.Unmarshal(input, &keyP)

		apkt := annotationPacket{}
		err = json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
		fmt.Println(err)
		key := []byte("passphrasewhichneedstobe32bytes!")
		ciphertext := apkt.WrappedKey

		c, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(c)

		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			fmt.Println(err)
		}

		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		protocolOuput := KeyProviderKeyWrapProtocolOuput{
			KeyUnwrapResults: KeyUnwrapResults{OptsData: unwrappedKey},
		}
		protocolOuputSerialized, _ := json.Marshal(protocolOuput)
		return protocolOuputSerialized, nil
	}
	return nil, errors.New("unkown protocol")
}

func TestKeyWrapKeyProviderSuccess(t *testing.T) {
	path := "config.json"
	os.Setenv("OCICRYPT_KEYPROVIDER_CONFIG", path)
	filecontent := `{"key-providers": {
                "keyprovider-1": {
                   "cmd": "/usr/lib/keyprovider-1-wrapkey",
                   "args": []
                }
        }}
        `
	filecontent2 := `{"key-providers": {
                "keyprovider-1": {
                   "cmd": "/usr/lib/keyprovider-1-unwrapkey",
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
		Parameters: parameters,
		DecryptConfig: config.DecryptConfig{},
	}
	runner = TestRunner{}
	keyWrapOutput, err := kewrapper.WrapKeys(&ec, optsData)
	assert.NoError(t, err)

	tempFile, _ = os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	tempFile.Write([]byte(filecontent2))
	tempFile.Close()
	dc := config.DecryptConfig{
		Parameters: nil,
	}
	keyUnWrapOutput, err := kewrapper.UnwrapKey(&dc, keyWrapOutput)
	assert.NoError(t, err)
	assert.Equal(t, optsData, keyUnWrapOutput)
	os.Remove(path) 
}

func init(){
	//lis := bufconn.Listen(1024 * 1024)
	lis, _ := net.Listen("tcp", ":50051")
	s := grpc.NewServer()
	keyproviderpb.RegisterKeyProviderServiceServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatal(err)
		}
	}()
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
		Parameters: parameters,
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
