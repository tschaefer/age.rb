package main

/*
#include <stdlib.h>

typedef struct {
	char* data;
	int length;
} AgeInput;

typedef struct {
	char** data;
	int* length;
} AgeOutput;

typedef struct {
	char** pubkey;
	char** privkey;
} AgeKeyPair;
*/
import "C"

import (
	"bytes"
	"io"
	"strings"
	"unsafe"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

func __performEncryption(input *C.AgeInput, output *C.AgeOutput, armored C.int, recipients ...age.Recipient) *C.char {
	var buffer bytes.Buffer
	var writer io.Writer = &buffer
	var armorWriter io.WriteCloser

	if armored != 0 {
		armorWriter = armor.NewWriter(writer)
		writer = armorWriter
	}

	encryptor, err := age.Encrypt(writer, recipients...)
	if err != nil {
		return C.CString("Error during encryption setup: " + err.Error())
	}

	plainBytes := C.GoBytes(unsafe.Pointer(input.data), C.int(input.length))
	if _, err := encryptor.Write(plainBytes); err != nil {
		return C.CString("Error during encryption: " + err.Error())
	}

	if err := encryptor.Close(); err != nil {
		return C.CString("Error closing encryption stream: " + err.Error())
	}

	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return C.CString("Error closing armor writer: " + err.Error())
		}
	}

	bytes := buffer.Bytes()
	*output.length = C.int(len(bytes))
	*output.data = (*C.char)(C.CBytes(bytes))

	return nil
}

func __performDecryption(input *C.AgeInput, output *C.AgeOutput, armored C.int, identities ...age.Identity) *C.char {
	encryptedBytes := C.GoBytes(unsafe.Pointer(input.data), C.int(input.length))
	var reader io.Reader = bytes.NewReader(encryptedBytes)

	if armored != 0 {
		reader = armor.NewReader(reader)
	}

	decryptor, err := age.Decrypt(reader, identities...)
	if err != nil {
		return C.CString("Error during decryption setup: " + err.Error())
	}

	var buffer bytes.Buffer
	if _, err = buffer.ReadFrom(decryptor); err != nil {
		return C.CString("Error during decryption: " + err.Error())
	}

	plainBytes := buffer.Bytes()
	*output.length = C.int(len(plainBytes))
	*output.data = (*C.char)(C.CBytes(plainBytes))

	return nil
}

//export encrypt
func encrypt(pubKeyStrs *C.char, input *C.AgeInput, output *C.AgeOutput, armored C.int) *C.char {
	pubKeyStrList := strings.Split(C.GoString(pubKeyStrs), ",")
	recipients := []age.Recipient{}

	for _, pubKeyStr := range pubKeyStrList {
		var pubKey age.Recipient
		var err error

		if strings.HasPrefix(pubKeyStr, "age1pq1") {
			pubKey, err = age.ParseHybridRecipient(pubKeyStr)
			if err != nil {
				return C.CString("Error parsing hybrid public key: " + err.Error())
			}
		} else {
			pubKey, err = age.ParseX25519Recipient(pubKeyStr)
			if err != nil {
				return C.CString("Error parsing public key: " + err.Error())
			}
		}
		recipients = append(recipients, pubKey)
	}

	return __performEncryption(input, output, armored, recipients...)
}

//export decrypt
func decrypt(privKeyStrs *C.char, input *C.AgeInput, output *C.AgeOutput, armored C.int) *C.char {
	privKeyStrList := strings.Split(C.GoString(privKeyStrs), ",")
	identities := []age.Identity{}

	for _, privKeyStr := range privKeyStrList {
		var privKey age.Identity
		var err error

		if strings.HasPrefix(privKeyStr, "AGE-SECRET-KEY-PQ") {
			privKey, err = age.ParseHybridIdentity(privKeyStr)
			if err != nil {
				return C.CString("Error parsing hybrid private key: " + err.Error())
			}
		} else {
			privKey, err = age.ParseX25519Identity(privKeyStr)
			if err != nil {
				return C.CString("Error parsing private key: " + err.Error())
			}
		}
		identities = append(identities, privKey)
	}

	return __performDecryption(input, output, armored, identities...)
}

//export generate_keypair
func generate_keypair(keypair *C.AgeKeyPair, pq C.int) *C.char {
	var pubKey string
	var privKey string

	if pq != 0 {
		identity, err := age.GenerateHybridIdentity()
		if err != nil {
			return C.CString("Error generating hybrid keypair: " + err.Error())
		}
		pubKey = identity.Recipient().String()
		privKey = identity.String()
	} else {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return C.CString("Error generating keypair: " + err.Error())
		}
		pubKey = identity.Recipient().String()
		privKey = identity.String()
	}

	*keypair.pubkey = C.CString(pubKey)
	*keypair.privkey = C.CString(privKey)

	return nil
}

//export encrypt_with_passphrase
func encrypt_with_passphrase(passphrase *C.char, input *C.AgeInput, output *C.AgeOutput, armored C.int) *C.char {
	recipient, err := age.NewScryptRecipient(C.GoString(passphrase))
	if err != nil {
		return C.CString("Error creating scrypt recipient: " + err.Error())
	}

	return __performEncryption(input, output, armored, recipient)
}

//export decrypt_with_passphrase
func decrypt_with_passphrase(passphrase *C.char, input *C.AgeInput, output *C.AgeOutput, armored C.int) *C.char {
	identity, err := age.NewScryptIdentity(C.GoString(passphrase))
	if err != nil {
		return C.CString("Error creating scrypt identity: " + err.Error())
	}

	return __performDecryption(input, output, armored, identity)
}

//export encrypt_with_ssh_keys
func encrypt_with_ssh_keys(sshPubKeyStrs *C.char, input *C.AgeInput, output *C.AgeOutput, armored C.int) *C.char {
	sshPubKeyStrList := strings.Split(C.GoString(sshPubKeyStrs), ",")
	recipients := []age.Recipient{}

	for _, sshPubKeyStr := range sshPubKeyStrList {
		recipient, err := agessh.ParseRecipient(sshPubKeyStr)
		if err != nil {
			return C.CString("Error parsing SSH public key: " + err.Error())
		}
		recipients = append(recipients, recipient)
	}

	return __performEncryption(input, output, armored, recipients...)
}

//export decrypt_with_ssh_keys
func decrypt_with_ssh_keys(sshPrivKeyStrs *C.char, input *C.AgeInput, output *C.AgeOutput, armored C.int) *C.char {
	sshPrivKeyStrList := strings.Split(C.GoString(sshPrivKeyStrs), ",")
	identities := []age.Identity{}

	for _, sshPrivKeyStr := range sshPrivKeyStrList {
		identity, err := agessh.ParseIdentity([]byte(sshPrivKeyStr))
		if err != nil {
			return C.CString("Error parsing SSH private key: " + err.Error())
		}
		identities = append(identities, identity)
	}

	return __performDecryption(input, output, armored, identities...)
}

//export free_memory
func free_memory(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func main() {}
