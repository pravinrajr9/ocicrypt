# Ocicrypt keyprovider protocol (Experimental)

Ocicrypt supports the use of an experimental keyprovider protocol. This allows the ability to encrypt and decrypt container image using the key that can be retrieved from any key management service.
The config file consists for list of protocols that can be used for either encryption. User can implement their own binary executable or grpc server for fetching the wrapped or unwrapped key from any key management service.

##Example of config

```code
"keyproviders": {
    "isecl": {
       "cmd": "/usr/lib/ocicrypt-isecl",   
       "args": []
    },
    "keyprotect": {
       "cmd": "/usr/lib/ocicrypt-keyprotect",   
       "args": []
    },
    "keyvault": {
       "grpc": "localhost:50051"
    }
}
```

##Passing of encryption/decryption keys
Passing of encryption and decryption keys would be implemented via "keyprovider:" prefix, followed by the
named prefix of the protocol, for example, the protocol "org.opencontainers.image.enc.keys.keyprovider.isecl"
would appear like the following:

```code
OCICRPYT_KEYPROVIDER_CONFIG=/etc/ocicrypt_keyprovider.json skopeo copy --encryption-key keyprovider:isecl:some-params
```

The same would follow for decryption config

```code
OCICRPYT_KEYPROVIDER_CONFIG=/etc/ocicrypt_keyprovider.json skopeo copy --decryption-key keyprovider:isecl:some-params
```