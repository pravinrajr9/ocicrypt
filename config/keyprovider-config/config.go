package keyprovider_config

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
)

type OcicryptConfig struct {
	KeyProviderConfig map[string]interface{} `json:"key-providers"`
}

const ENVVARNAME = "OCICRYPT_KEYPROVIDER_CONFIG"

// parseConfigFile parses a configuration file; it is not an error if the configuration file does
// not exist, so no error is returned.
func parseConfigFile(filename string) (*OcicryptConfig, error) {
	// a non-existent config file is not an error
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return nil, nil
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ic := &OcicryptConfig{}
	err = json.Unmarshal(data, ic)
	return ic, err
}

// getConfiguration tries to read the configuration file at the following locations
// ${OCICRYPT_KEYPROVIDER_CONFIG} == "/etc/ocicrypt_keyprovider.yaml"
// If no configuration file could be found or read a null pointer is returned
func GetConfiguration() (*OcicryptConfig, error) {
	var ic *OcicryptConfig
	var err error
	filename := os.Getenv(ENVVARNAME)
	if len(filename) > 0 {
		ic, err = parseConfigFile(filename)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New(ENVVARNAME + "doesnt contain config file")
	}
	return ic, nil
}

