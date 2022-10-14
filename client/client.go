package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return nil, err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return nil, err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	//username of the user
	username string
	
	//private key for protection it's own information
	PrivateKeys []byte
	
	//sign key
	SignKey userlib.DSSignKey
	
	//decryption key
	DecryptionKey userlib.PKEDecKey
	
	//uuid of dynamic user values
	DynamicUserUUID uuid.UUID
	
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type DynamicUser struct {
	//list of the hash file names it has access to (each is 64 bytes)
	Filenames []byte
	
	//list of uuids of the pib's of for the files above
	PipUUIDs []uuid.UUID
}

type PreInvitationPointer struct {
	//uuid of the ip
	IpUUID uuid.UUID
	
	//keys of the ip (symmetric 16 byte keys)
	IpKeys []byte
	
	//uuid of the cip
	CipUUID uuid.UUID
	
	//keys of the cip (symmetric 16 byte keys)
	CipKeys []byte
}

type InvitationPointer struct {
	//uuid of the parent ib or file 
	ParentUUID uuid.UUID
	
	//keys of the parent ib or the file
	//symmetric encryption using 16 byte keys
	ParentKeys []byte
	
	//if this is the origin/root node in the ib tree
	IsOrigin bool
}

type ChildInvitationPointer struct {
	//children uuids
	ChildrenUUIDs []uuid.UUID
	
	//children keys (symmetric 16 byte keys)
	ChildrenKeys []byte
	
	//corresponding has of the username for the cip
	UsernameHash []byte
	
	//corresponding ip uuid
	IpUUID uuid.UUID
	
	//corresponding pip uuid
	PipUUID uuid.UUID
}

type FileContainer struct {	
	//uuid of first filelink
	First uuid.UUID
	
	//uuid of last filelink
	Last uuid.UUID
}

type FileLink struct {
	//uuid of next file link
	Next uuid.UUID
	
	//uuid of file fragment
	FragmentUUID uuid.UUID
}

type InvitationContainer struct {
	//uuid of the ip
	IpUUID uuid.UUID
	
	//keys of the ip (symmetric 16 byte keys)
	IpKeys []byte
	
	//uuid of the cip
	CipUUID uuid.UUID
	
	//keys of the cip (symmetric 16 byte keys)
	CipKeys []byte
}

type InvitationMessage struct {
	//uuid of the ic
	IcUUID uuid.UUID
	
	//keys of the ic
	IcKeys []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	//check if username length is 0
	if len([]rune(username)) == 0 {
		return nil, errors.New("username is of length 0")
	}
	
	//check if user already exists
	user_from_bytes, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	
	if err != nil {
		return nil, errors.New("cannot get user from bytes")
	}
	
	_, success := userlib.DatastoreGet(user_from_bytes)
	
	//if user exists
	if success {
		return nil, errors.New("user already exists")
	}

	//create private and public key pair for private key encryption
	var kp_pke userlib.PKEEncKey
	var ks_pke userlib.PKEDecKey
	kp_pke, ks_pke, _ = userlib.PKEKeyGen()
	
	//create private and public key pair for digital signatures
	var kp_ds userlib.DSVerifyKey
	var ks_ds userlib.DSSignKey
	ks_ds, kp_ds, _ = userlib.DSKeyGen()
	
	//create private key for encryption and decryption
	var ks_priv []byte = append(userlib.RandomBytes(16), userlib.RandomBytes(16)...)
	
	//store public keys in keystore
	err = userlib.KeystoreSet(string(userlib.Hash([]byte(username + "pke"))) , kp_pke)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	err = userlib.KeystoreSet(string(userlib.Hash([]byte(username + "ds"))) , kp_ds)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//create dynamic user uuid
	var dynamic_user_uuid uuid.UUID = uuid.New()
	
	//create dynamic user
	var dynamic_user DynamicUser

	//create user namespace struct
	var user_namespace User
	
	//set the values of the namespace struct
	user_namespace.username = username
	user_namespace.PrivateKeys = ks_priv
	user_namespace.SignKey = ks_ds
	user_namespace.DecryptionKey = ks_pke
	user_namespace.DynamicUserUUID = dynamic_user_uuid

	//--store dynamic user in datastore--
	
	//marshal dynamic user
	marshaled_du, err := json.Marshal(&dynamic_user)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//store dynamic user
	err = StorePrivateContent(user_namespace.PrivateKeys[0: 16], user_namespace.PrivateKeys[16: 32], dynamic_user_uuid, marshaled_du)
	
	//check for error
	if err != nil {
		return nil, err
	}

	//--store namespace in datastore--
	
	//protected by the hash of the password and username
	marshaled_user_namespace, err := json.Marshal(&user_namespace)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//get uuid for namespace
	username_namespace_uuid, err := uuid.FromBytes(userlib.Hash([]byte(username + "namespace"))[:16])
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//compute hash of password and username
	var user_password_hash = userlib.Hash([]byte(username + password))
	var password_user_hash = userlib.Hash([]byte(password + username))
	
	//store user namespace
	err = StorePrivateContent(password_user_hash[:16], user_password_hash[:16], username_namespace_uuid, marshaled_user_namespace)
	
	if err != nil {
		return nil, err
	}
	
	//store user password check
	err = StorePrivateContent(password_user_hash[:16], user_password_hash[:16], user_from_bytes, userlib.Hash([]byte(username)))
	
	if err != nil {
		return nil, err
	}
	
	return &user_namespace, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	//check if user already exists
	user_from_bytes, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	
	if err != nil {
		return nil, errors.New("cannot get user from bytes")
	}
	
	//compute hash of password and username
	var user_password_hash = userlib.Hash([]byte(username + password))
	var password_user_hash = userlib.Hash([]byte(password + username))
	
	data, err := DecryptPrivateContent(password_user_hash[:16], user_password_hash[:16], user_from_bytes)
	
	if err != nil {
		return nil, err
	}
	
	//check if it had been tampered with (second time)
	if !userlib.HMACEqual(data, userlib.Hash([]byte(username))) {
		return nil, errors.New("usernames do not match")
	}
	
	var user_namespace_uuid uuid.UUID
	user_namespace_uuid, err = uuid.FromBytes(userlib.Hash([]byte(username + "namespace"))[:16])
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	var user_namespace User
	decrypted_content, err := DecryptPrivateContent(password_user_hash[:16], user_password_hash[:16], user_namespace_uuid)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//unmarshal content to namespace
	err = json.Unmarshal(decrypted_content, &user_namespace)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	return &user_namespace, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//get dynamic user
	unmarshaled_du, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID)
	
	//unmarshal dynamic user
	var dynamic_user DynamicUser
	err = json.Unmarshal(unmarshaled_du, &dynamic_user)
	
	//check for error
	if err != nil {
		return err
	}
	
	//pip uuid
	var pip_uuid uuid.UUID = uuid.Nil
	
	//get hash of file name
	var filename_hash []byte = userlib.Hash([]byte(filename))
	
	var i int
	
	//attempt to find the filename in the user_namespace filenames
	for i = 0; i < len(dynamic_user.PipUUIDs); i ++ {
		if userlib.HMACEqual(dynamic_user.Filenames[i * 64: (i + 1) * 64], filename_hash) {
			pip_uuid = dynamic_user.PipUUIDs[i]
			break
		}
	}
	
	if pip_uuid != uuid.Nil {
		//get pip data
		unmarshaled_pip, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[16:32], pip_uuid)
		
		//check for error
		if err != nil {
			//remove filename from user's files
			dynamic_user.Filenames = append(dynamic_user.Filenames[:i * 64], dynamic_user.Filenames[(i + 1) * 64:]...)
			dynamic_user.PipUUIDs = append(dynamic_user.PipUUIDs[:i], dynamic_user.PipUUIDs[(i + 1):]...)
		} else {
			//unmarshal pip
			var pre_invitation_pointer PreInvitationPointer
			err = json.Unmarshal(unmarshaled_pip, &pre_invitation_pointer)
			
			//check for error
			if err != nil {
				return err
			}
			
			//get origin invitation pointer
			origin_invitation_pointer, origin_keys, origin_uuid, err := ClimbUpInvitationPointerTreeGetOrigin(pre_invitation_pointer.IpKeys, pre_invitation_pointer.IpUUID)
			
			//check for error
			if err != nil {
				return err
			}
			
			//delete previous file
			_, err = RemoveFileContents(origin_invitation_pointer.ParentKeys, origin_invitation_pointer.ParentUUID)
			
			//check for error
			if err != nil {
				return err
			}
			
			//create new file
			new_file_keys, new_file_uuid, err := CreateFileContents(content)
			
			//check for error
			if err != nil {
				return err
			}

			//set origin ip values
			origin_invitation_pointer.ParentKeys = new_file_keys
			origin_invitation_pointer.ParentUUID = new_file_uuid
			
			//marshal origin ip
			marshaled_ip, err := json.Marshal(&origin_invitation_pointer)
			
			//check for error
			if err != nil {
				return err
			}
			
			//store origin ip
			err = StorePrivateContent(origin_keys[0:16], origin_keys[16:32], origin_uuid, marshaled_ip)
			
			//check for error
			if err != nil {
				return err
			}
		}
	} else {
		//uuids
		var pip_uuid = uuid.New()
		var ip_uuid = uuid.New()
		var cip_uuid = uuid.New()
		
		//create file
		file_keys, file_uuid, err := CreateFileContents(content)
		
		//check for error
		if err != nil {
			return err
		}
		
		//create keys
		var ip_keys = append(userlib.RandomBytes(16), userlib.RandomBytes(16)...)
		var cip_keys = append(userlib.RandomBytes(16), userlib.RandomBytes(16)...)
		
		//create ip
		var invitation_pointer InvitationPointer
		invitation_pointer.ParentUUID = file_uuid
		invitation_pointer.ParentKeys = file_keys
		invitation_pointer.IsOrigin = true
		
		//create pip
		var pre_invitation_pointer PreInvitationPointer
		pre_invitation_pointer.IpUUID = ip_uuid
		pre_invitation_pointer.IpKeys = ip_keys
		pre_invitation_pointer.CipUUID = cip_uuid
		pre_invitation_pointer.CipKeys = cip_keys
		
		//create cip
		var children_invitation_pointer ChildInvitationPointer
		children_invitation_pointer.UsernameHash = userlib.Hash([]byte(userdata.username))
		children_invitation_pointer.IpUUID = ip_uuid
		children_invitation_pointer.PipUUID = pip_uuid
		
		//marshal pip
		marshaled_pip, err := json.Marshal(&pre_invitation_pointer)
		
		//check for error
		if err != nil {
			return err
		}
		
		//store pip
		err = StorePrivateContent(userdata.PrivateKeys[0: 16], userdata.PrivateKeys[16: 32], pip_uuid, marshaled_pip)
		
		//check for error
		if err != nil {
			return err
		}
		
		//set ip values
		invitation_pointer.ParentKeys = file_keys
		invitation_pointer.ParentUUID = file_uuid
		
		//marshal ip
		marshaled_ip, err := json.Marshal(&invitation_pointer)
		
		//check for error
		if err != nil {
			return err
		}
		
		//store ip
		err = StorePrivateContent(ip_keys[0:16], ip_keys[16:32], ip_uuid, marshaled_ip)
		
		//check for error
		if err != nil {
			return err
		}
		
		//marshal cip
		marshaled_cip, err := json.Marshal(&children_invitation_pointer)
		
		//check for error
		if err != nil {
			return err
		}
		
		//store cip
		err = StorePrivateContent(cip_keys[0:16], cip_keys[16:32], cip_uuid, marshaled_cip)
		
		//check for error
		if err != nil {
			return err
		}

		//add hash of file name and uuid to dynamic user
		dynamic_user.Filenames = append(dynamic_user.Filenames, userlib.Hash([]byte(filename))...)
		
		//add pip to user namespace
		dynamic_user.PipUUIDs = append(dynamic_user.PipUUIDs, pip_uuid)
	}
	
	//mashal dynamic user
	marshaled_du, err := json.Marshal(&dynamic_user)
	
	if err != nil {
		return err
	}
	
	//rewrite to datastore
	err = StorePrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID, marshaled_du) 
	
	//check for error
	if err != nil {
		return err
	}
	
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	//pip uuid
	var pip_uuid uuid.UUID = uuid.Nil
	
	//get hash of file name
	var filename_hash []byte = userlib.Hash([]byte(filename))
	
	//get dynamic user
	unmarshaled_du, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID)
	
	//unmarshal dynamic user
	var dynamic_user DynamicUser
	err = json.Unmarshal(unmarshaled_du, &dynamic_user)
	
	//check for error
	if err != nil {
		return err
	}
	
	var i int

	//attempt to find the filename in the user_namespace filenames
	for i = 0; i < len(dynamic_user.PipUUIDs); i ++ {
		if userlib.HMACEqual(dynamic_user.Filenames[i * 64: (i + 1) * 64], filename_hash) {
			pip_uuid = dynamic_user.PipUUIDs[i]
			break
		}
	}
	
	if pip_uuid == uuid.Nil {
		return errors.New("filename was not found")
	}

	//get pip data
	unmarshaled_pip, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[16:32], pip_uuid)
	
	//check for error
	if err != nil {
		var original_error error = err
	
		//remove filename from user's files
		dynamic_user.Filenames = append(dynamic_user.Filenames[:i * 64], dynamic_user.Filenames[(i + 1) * 64:]...)
		dynamic_user.PipUUIDs = append(dynamic_user.PipUUIDs[:i], dynamic_user.PipUUIDs[(i + 1):]...)
		
		//mashal dynamic user
		marshaled_du, err := json.Marshal(&dynamic_user)
		
		if err != nil {
			return err
		}
		
		//rewrite to datastore
		err = StorePrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID, marshaled_du) 
		
		//check for error
		if err != nil {
			return err
		}
		
		return original_error
	}
	
	//unmarshal pip
	var pre_invitation_pointer PreInvitationPointer
	err = json.Unmarshal(unmarshaled_pip, &pre_invitation_pointer)
	
	//check for error
	if err != nil {
		return err
	}
	
	//get file keys and uuid
	file_keys, file_uuid, err := ClimbUpInvitationPointerTree(pre_invitation_pointer.IpKeys, pre_invitation_pointer.IpUUID)
	
	//check for error
	if err != nil {
		return err
	}
	
	//get the file container
	unmarshaled_file_container, err := DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_uuid)
	
	//check for error
	if err != nil {
		return err
	}
	
	//unmarshal file container
	var file_container FileContainer
	err = json.Unmarshal(unmarshaled_file_container, &file_container)
	
	//check for error
	if err != nil {
		return err
	}
	
	//get the last file link
	unmarshaled_file_link, err := DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_container.Last)
	
	//check for error
	if err != nil {
		return err
	}
	
	//unmarshal file link
	var last_file_link FileLink
	err = json.Unmarshal(unmarshaled_file_link, &last_file_link)

	//check for error
	if err != nil {
		return err
	}
	
	//create uuids
	var next_file_link_uuid uuid.UUID = uuid.New()
	var file_fragment_uuid uuid.UUID = uuid.New()
	
	//create next file link
	var next_file_link FileLink
	
	next_file_link.FragmentUUID = file_fragment_uuid
	last_file_link.Next = next_file_link_uuid
	
	//marshal next file link
	marshaled_nfl, err := json.Marshal(&next_file_link)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store next file link
	err = StorePrivateContent(file_keys[0:16], file_keys[16:32], next_file_link_uuid, marshaled_nfl)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store file fragment
	err = StorePrivateContent(file_keys[0:16], file_keys[16:32], file_fragment_uuid, content)
	
	//check for error
	if err != nil {
		return err
	}
	
	//marshal last file link
	marshaled_lfl, err := json.Marshal(&last_file_link)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store last file link
	err = StorePrivateContent(file_keys[0:16], file_keys[16:32], file_container.Last, marshaled_lfl)
	
	//check for error
	if err != nil {
		return err
	}
	
	file_container.Last = next_file_link_uuid
	
	//marshal file container
	marshaled_fc, err := json.Marshal(&file_container)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store file container
	err = StorePrivateContent(file_keys[0:16], file_keys[16:32], file_uuid, marshaled_fc)
	
	//check for error
	if err != nil {
		return err
	}
	
	/*
	
	//get the file container
	unmarshaled_file_container, err := DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_uuid)
	
	//unmarshal file container
	var file_container FileContainer
	err = json.Unmarshal(unmarshaled_file_container, &file_container)
	
	//check for error
	if err != nil {
		return err
	}
	
	//create file fragment uuid
	var file_fragment_uuid uuid.UUID = uuid.New()
	
	//store content
	err = StorePrivateContent(file_keys[0:16], file_keys[16:32], file_fragment_uuid, content)
	
	//check for error
	if err != nil {
		return err
	}
	
	//add file fragment uuid to file container 
	file_container.FragmentUUIDs = append(file_container.FragmentUUIDs, file_fragment_uuid)
	
	//mashal file container
	marshaled_file_container, err := json.Marshal(&file_container)
	
	if err != nil {
		return err
	}
	
	//rewrite file container
	err = StorePrivateContent(file_keys[0:16], file_keys[16:32], file_uuid, marshaled_file_container)
	
	if err != nil {
		return err
	}*/

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//pip uuid
	var pip_uuid uuid.UUID = uuid.Nil
	
	//get hash of file name
	var filename_hash []byte = userlib.Hash([]byte(filename))
	
	//get dynamic user
	unmarshaled_du, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID)
	
	//unmarshal dynamic user
	var dynamic_user DynamicUser
	err = json.Unmarshal(unmarshaled_du, &dynamic_user)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	var i int

	//attempt to find the filename in the user_namespace filenames
	for i = 0; i < len(dynamic_user.PipUUIDs); i ++ {
		if userlib.HMACEqual(dynamic_user.Filenames[i * 64: (i + 1) * 64], filename_hash) {
			pip_uuid = dynamic_user.PipUUIDs[i]
			break
		}
	}
	
	if pip_uuid == uuid.Nil {
		return nil, errors.New("filename was not found")
	}

	//get pip data
	unmarshaled_pip, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[16:32], pip_uuid)
	
	//check for error
	if err != nil {
		var original_error error = err
	
		//remove filename from user's files
		dynamic_user.Filenames = append(dynamic_user.Filenames[:i * 64], dynamic_user.Filenames[(i + 1) * 64:]...)
		dynamic_user.PipUUIDs = append(dynamic_user.PipUUIDs[:i], dynamic_user.PipUUIDs[(i + 1):]...)
		
		//mashal dynamic user
		marshaled_du, err := json.Marshal(&dynamic_user)
		
		if err != nil {
			return nil, err
		}
		
		//rewrite to datastore
		err = StorePrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID, marshaled_du) 
		
		//check for error
		if err != nil {
			return nil, err
		}
		
		return nil, original_error
	}
	
	//unmarshal pip
	var pre_invitation_pointer PreInvitationPointer
	err = json.Unmarshal(unmarshaled_pip, &pre_invitation_pointer)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//get file keys and uuid
	file_keys, file_uuid, err := ClimbUpInvitationPointerTree(pre_invitation_pointer.IpKeys, pre_invitation_pointer.IpUUID)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//get the file container
	unmarshaled_file_container, err := DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_uuid)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//unmarshal file container
	var file_container FileContainer
	err = json.Unmarshal(unmarshaled_file_container, &file_container)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//loop variables
	var file_link_uuid uuid.UUID = file_container.First
	var unmarshaled_file_link []byte
	var file_link FileLink
	var file_fragment_content []byte
	var file_content []byte
	
	for true {	
		//get the file link
		unmarshaled_file_link, err = DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_link_uuid)
		
		//check for error
		if err != nil {
			return nil, err
		}
		
		//unmarshal file link
		err = json.Unmarshal(unmarshaled_file_link, &file_link)
	
		//check for error
		if err != nil {
			return nil, err
		}
		
		//get file fragment
		file_fragment_content, err = DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_link.FragmentUUID)
	
		//check for error
		if err != nil {
			return nil, err
		}
		
		//add fragment content to current content
		file_content = append(file_content, file_fragment_content...)
		
		//if we have reached end of link chain
		if file_link.Next == uuid.Nil {
			break
		}

		//set next link uuid
		file_link_uuid = file_link.Next
	}
	
	return file_content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//get recipients encryption key
	recipient_kp_pke, success := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "pke"))))
	
	//check for error
	if !success {
		return uuid.Nil, errors.New("could not find public key in keystore, user does not exist")
	}
	
	//pip uuid
	var pip_uuid uuid.UUID = uuid.Nil
	
	//get hash of file name
	var filename_hash []byte = userlib.Hash([]byte(filename))

	//get dynamic user
	unmarshaled_du, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID)
	
	//unmarshal dynamic user
	var dynamic_user DynamicUser
	err = json.Unmarshal(unmarshaled_du, &dynamic_user)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}

	//attempt to find the filename in the user_namespace filenames
	for i := 0; i < len(dynamic_user.PipUUIDs); i ++ {
		if userlib.HMACEqual(dynamic_user.Filenames[i * 64: (i + 1) * 64], filename_hash) {
			pip_uuid = dynamic_user.PipUUIDs[i]
			break
		}
	}
	
	if pip_uuid == uuid.Nil {
		return uuid.Nil, errors.New("filename does not exist")
	}

	//get pip data
	unmarshaled_pip, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[16:32], pip_uuid)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//unmarshal pip
	var pre_invitation_pointer PreInvitationPointer
	err = json.Unmarshal(unmarshaled_pip, &pre_invitation_pointer)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//uuids
	var ip_uuid = uuid.New()
	var cip_uuid = uuid.New()
	var ic_uuid = uuid.New()
	var im_uuid = uuid.New()
	
	//create keys
	var ip_keys = append(userlib.RandomBytes(16), userlib.RandomBytes(16)...)
	var cip_keys = append(userlib.RandomBytes(16), userlib.RandomBytes(16)...)
	
	//create ip
	var recipient_invitation_pointer InvitationPointer
	recipient_invitation_pointer.ParentUUID = pre_invitation_pointer.IpUUID
	recipient_invitation_pointer.ParentKeys = pre_invitation_pointer.IpKeys
	recipient_invitation_pointer.IsOrigin = false
	
	//create cip
	var recipient_children_invitation_pointer ChildInvitationPointer
	recipient_children_invitation_pointer.UsernameHash = userlib.Hash([]byte(recipientUsername))
	recipient_children_invitation_pointer.IpUUID = ip_uuid
	
	//get cip
	var children_invitation_pointer ChildInvitationPointer
	decrypted_cip, err := DecryptPrivateContent(pre_invitation_pointer.CipKeys[0:16], pre_invitation_pointer.CipKeys[16:32], pre_invitation_pointer.CipUUID)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//unmarshal content to namespace
	err = json.Unmarshal(decrypted_cip, &children_invitation_pointer)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//add recipient cip as child of this cip
	children_invitation_pointer.ChildrenUUIDs = append(children_invitation_pointer.ChildrenUUIDs, cip_uuid)
	children_invitation_pointer.ChildrenKeys = append(children_invitation_pointer.ChildrenKeys, cip_keys...)
	
	//marshal cip
	marshaled_cip, err := json.Marshal(&children_invitation_pointer)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//store modified cip
	err = StorePrivateContent(pre_invitation_pointer.CipKeys[0:16], pre_invitation_pointer.CipKeys[16:32], pre_invitation_pointer.CipUUID, marshaled_cip)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//marshal ip
	marshaled_r_ip, err := json.Marshal(&recipient_invitation_pointer)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//store recipient ip
	err = StorePrivateContent(ip_keys[0:16], ip_keys[16:32], ip_uuid, marshaled_r_ip)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//marshal cip
	marshaled_r_cip, err := json.Marshal(&recipient_children_invitation_pointer)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//store recipient cip
	err = StorePrivateContent(cip_keys[0:16], cip_keys[16:32], cip_uuid, marshaled_r_cip)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//create invitation container information
	ic_keys := append(userlib.RandomBytes(16), userlib.RandomBytes(16)...)
	var invitation_container InvitationContainer
	
	//store infomation in invitation container
	invitation_container.IpUUID = ip_uuid
	invitation_container.IpKeys = ip_keys
	invitation_container.CipUUID = cip_uuid
	invitation_container.CipKeys = cip_keys
	
	//create invitation message information
	var invitation_message InvitationMessage
	
	//store information in invitation message
	invitation_message.IcUUID = ic_uuid
	invitation_message.IcKeys = ic_keys
	
	//marshal ic
	marshaled_ic, err := json.Marshal(&invitation_container)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//store recipient ic
	err = StorePrivateContent(ic_keys[0:16], ic_keys[16:32], ic_uuid, marshaled_ic)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//--store invitation by encrypting with recipeint's public encryption key and sign with current user's sign key--
	
	//marshal im
	marshaled_im, err := json.Marshal(&invitation_message)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//encode invitation message with first key
	encoded_im, err := userlib.PKEEnc(recipient_kp_pke, marshaled_im)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//mac container with second key
	signed_im, err := userlib.DSSign(userdata.SignKey, encoded_im)
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	//store the invitation
	userlib.DatastoreSet(im_uuid, append(signed_im, encoded_im...))
	
	//check for error
	if err != nil {
		return uuid.Nil, err
	}
	
	return im_uuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//pip uuid
	var pip_uuid uuid.UUID = uuid.Nil
	
	//get hash of file name
	var filename_hash []byte = userlib.Hash([]byte(filename))
	
	//get dynamic user
	unmarshaled_du, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID)
	
	//unmarshal dynamic user
	var dynamic_user DynamicUser
	err = json.Unmarshal(unmarshaled_du, &dynamic_user)
	
	//check for error
	if err != nil {
		return err
	}
	
	//attempt to find the filename in the user_namespace filenames
	for i := 0; i < len(dynamic_user.PipUUIDs); i ++ {
		if userlib.HMACEqual(dynamic_user.Filenames[i * 64: (i + 1) * 64], filename_hash) {
			pip_uuid = dynamic_user.PipUUIDs[i]
			break
		}
	}
	
	if pip_uuid != uuid.Nil {
		return errors.New("filename already exists")
	}
	
	//get sending user's verify key
	recipient_kp_ds, success := userlib.KeystoreGet(string(userlib.Hash([]byte(senderUsername + "ds"))))
	
	//check for error
	if !success {
		return errors.New("Could not get sender's public verify key from keystore")
	}
	
	//get invitation message
	data, success := userlib.DatastoreGet(invitationPtr)
	
	//check for error, or if could not find namespace
	if !success {
		return errors.New("could not find invitation message in datastore")
	}
	
	//make sure there are more than 256 bytes
	if (len(data) <= 256) {
		return errors.New("data is not long enough")
	}
	
	//compute mac of remaning data
	err = userlib.DSVerify(recipient_kp_ds, data[256:], data[0:256])
	
	//check for error
	if err != nil {
		return err
	}
	
	//decrypt rest of data
	unmarshaled_im, err := userlib.PKEDec(userdata.DecryptionKey, data[256:])
	
	//check for error
	if err != nil {
		return err
	}
	
	//unmarshal invitation message
	var invitation_message InvitationMessage
	err = json.Unmarshal(unmarshaled_im, &invitation_message)
	
	//check for error
	if err != nil {
		return err
	}
	
	//get the invitation container
	unmarshaled_ic, err := DecryptPrivateContent(invitation_message.IcKeys[0:16], invitation_message.IcKeys[16:32], invitation_message.IcUUID)
	
	//check for error
	if err != nil {
		return err
	}
	
	//unmarshal invitation container
	var invitation_container InvitationContainer
	err = json.Unmarshal(unmarshaled_ic, &invitation_container)
	
	//check for error
	if err != nil {
		return err
	}
	
	//--check that cip and pip exist--
	data, err = DecryptPrivateContent(invitation_container.IpKeys[0:16], invitation_container.IpKeys[16:32], invitation_container.IpUUID)
	
	if err != nil {
		return err
	}
	
	data, err = DecryptPrivateContent(invitation_container.CipKeys[0:16], invitation_container.CipKeys[16:32], invitation_container.CipUUID)
	
	if err != nil {
		return err
	}
	
	//unmarshal cip
	var children_invitation_pointer ChildInvitationPointer
	err = json.Unmarshal(data, &children_invitation_pointer)
	
	//check for error
	if err != nil {
		return err
	}
	
	//create uuids
	pip_uuid = uuid.New()
	
	//create pip
	var pre_invitation_pointer PreInvitationPointer
	pre_invitation_pointer.IpUUID = invitation_container.IpUUID
	pre_invitation_pointer.IpKeys = invitation_container.IpKeys
	pre_invitation_pointer.CipUUID = invitation_container.CipUUID
	pre_invitation_pointer.CipKeys = invitation_container.CipKeys

	//marshal pip
	marshaled_pip, err := json.Marshal(&pre_invitation_pointer)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store modified pip
	err = StorePrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[16:32], pip_uuid, marshaled_pip)
	
	//check for error
	if err != nil {
		return err
	}
	
	//add values to cip
	children_invitation_pointer.PipUUID = pip_uuid
	
	//marshal cip
	marshaled_cip, err := json.Marshal(&children_invitation_pointer)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store modified cip
	err = StorePrivateContent(invitation_container.CipKeys[0:16], invitation_container.CipKeys[16:32], invitation_container.CipUUID, marshaled_cip)
	
	//check for error
	if err != nil {
		return err
	}
	
	//add hash of file name and uuid to dynamic user
	dynamic_user.Filenames = append(dynamic_user.Filenames, userlib.Hash([]byte(filename))...)
	
	//add pip to user namespace
	dynamic_user.PipUUIDs = append(dynamic_user.PipUUIDs, pip_uuid)
	
	//mashal dynamic user
	marshaled_du, err := json.Marshal(&dynamic_user)
	
	if err != nil {
		return err
	}
	
	//rewrite to datastore
	err = StorePrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID, marshaled_du) 
	
	//check for error
	if err != nil {
		return err
	}
	
	//delete invitation container and message
	userlib.DatastoreDelete(invitation_message.IcUUID)
	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//pip uuid
	var pip_uuid uuid.UUID = uuid.Nil
	
	//get hash of file name
	var filename_hash []byte = userlib.Hash([]byte(filename))
	
	//get dynamic user
	unmarshaled_du, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID)
	
	//unmarshal dynamic user
	var dynamic_user DynamicUser
	err = json.Unmarshal(unmarshaled_du, &dynamic_user)
	
	//check for error
	if err != nil {
		return err
	}
	
	var i int

	//attempt to find the filename in the user_namespace filenames
	for i = 0; i < len(dynamic_user.PipUUIDs); i ++ {
		if userlib.HMACEqual(dynamic_user.Filenames[i * 64: (i + 1) * 64], filename_hash) {
			pip_uuid = dynamic_user.PipUUIDs[i]
			break
		}
	}
	
	if pip_uuid == uuid.Nil {
		return errors.New("filename was not found")
	}

	//get pip data
	unmarshaled_pip, err := DecryptPrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[16:32], pip_uuid)
	
	//check for error
	if err != nil {
		var original_error error = err
	
		//remove filename from user's files
		dynamic_user.Filenames = append(dynamic_user.Filenames[:i * 64], dynamic_user.Filenames[(i + 1) * 64:]...)
		dynamic_user.PipUUIDs = append(dynamic_user.PipUUIDs[:i], dynamic_user.PipUUIDs[(i + 1):]...)
		
		//mashal dynamic user
		marshaled_du, err := json.Marshal(&dynamic_user)
		
		if err != nil {
			return err
		}
		
		//rewrite to datastore
		err = StorePrivateContent(userdata.PrivateKeys[0:16], userdata.PrivateKeys[0:16][16:32], userdata.DynamicUserUUID, marshaled_du) 
		
		//check for error
		if err != nil {
			return err
		}
		
		return original_error
	}
	
	//unmarshal pip
	var pre_invitation_pointer PreInvitationPointer
	err = json.Unmarshal(unmarshaled_pip, &pre_invitation_pointer)
	
	//check for error
	if err != nil {
		return err
	}
	
	found_cip_keys, found_cip_uuid, _, err := FindCipChild(pre_invitation_pointer.CipKeys, pre_invitation_pointer.CipUUID, userlib.Hash([]byte(recipientUsername)))
	
	//check for error
	if err != nil {
		return err
	}
	
	if found_cip_uuid == uuid.Nil {
		return errors.New("user was not found as a valid recipient")
	}
	
	//recursivly delete children invitation pointer references
	err = RevokeCipChildren(found_cip_keys, found_cip_uuid)	
	
	//check for error
	if err != nil {
		return err
	}
	
	//get the origin ip
	origin_invitation_pointer, origin_ip_keys, origin_ip_uuid, err := ClimbUpInvitationPointerTreeGetOrigin(pre_invitation_pointer.IpKeys, pre_invitation_pointer.IpUUID)
	
	//delete file
	content, err := RemoveFileContents(origin_invitation_pointer.ParentKeys, origin_invitation_pointer.ParentUUID)
	
	//check for error
	if err != nil {
		return err
	}
	
	file_keys, file_uuid, err := CreateFileContents(content)
	
	//check for error
	if err != nil {
		return err
	}
	
	//set origin ip values
	origin_invitation_pointer.ParentKeys = file_keys
	origin_invitation_pointer.ParentUUID = file_uuid
	
	//marshal origin ip
	marshaled_ip, err := json.Marshal(&origin_invitation_pointer)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store origin ip
	err = StorePrivateContent(origin_ip_keys[0:16], origin_ip_keys[16:32], origin_ip_uuid, marshaled_ip)
	
	//check for error
	if err != nil {
		return err
	}
	
	return nil
}

//--helper methods--

func FindCipChild(cip_keys []byte, cip_uuid uuid.UUID, username_hash []byte) ([]byte, uuid.UUID, bool, error){
	//get the cip
	unmarshaled_cip, err := DecryptPrivateContent(cip_keys[0:16], cip_keys[16:32], cip_uuid)
	
	//check for error
	if err != nil {
		return nil, uuid.Nil, false, err
	}
	
	//unmarshal cip
	var children_invitation_pointer ChildInvitationPointer
	err = json.Unmarshal(unmarshaled_cip, &children_invitation_pointer)
	
	//check for error
	if err != nil {
		return nil, uuid.Nil, false, err
	}
	
	//if we found it
	if userlib.HMACEqual(children_invitation_pointer.UsernameHash, username_hash) {
		return cip_keys, cip_uuid, true, nil
	}
	
	//children cip values
	var child_cip_keys []byte
	var child_cip_uuid uuid.UUID
	var is_parent bool
	
	//iterate though children
	for i := 0; i < len(children_invitation_pointer.ChildrenUUIDs); i ++ {	
		//get the child cip
		child_cip_keys, child_cip_uuid, is_parent, err = FindCipChild(children_invitation_pointer.ChildrenKeys[i * 32: (i + 1) * 32], children_invitation_pointer.ChildrenUUIDs[i], username_hash)
	
		//check for error
		if err != nil {
			return nil, uuid.Nil, false, err
		}
		
		//if it was found
		if child_cip_uuid != uuid.Nil {
			//if we are the direct parent
			if is_parent {
				//remove child from list
				children_invitation_pointer.ChildrenUUIDs = append(children_invitation_pointer.ChildrenUUIDs[:i], children_invitation_pointer.ChildrenUUIDs[i + 1:]...)
				children_invitation_pointer.ChildrenKeys = append(children_invitation_pointer.ChildrenKeys[:(i * 32)], children_invitation_pointer.ChildrenKeys[(i + 1) * 32:]...)
				
				//marshal cip
				marshaled_cip, err := json.Marshal(&children_invitation_pointer)
				
				//check for error
				if err != nil {
					return nil, uuid.Nil, false, err
				}
				
				//store modified cip
				err = StorePrivateContent(cip_keys[0:16], cip_keys[16:32], cip_uuid, marshaled_cip)
				
				//check for error
				if err != nil {
					return nil, uuid.Nil, false, err
				}
			}
		
			return child_cip_keys, child_cip_uuid, false, nil
		}
	}
	
	return nil, uuid.Nil, false, nil
}

func RevokeCipChildren(cip_keys []byte, cip_uuid uuid.UUID) (error) {
	//get the cip
	unmarshaled_cip, err := DecryptPrivateContent(cip_keys[0:16], cip_keys[16:32], cip_uuid)
	
	//check for error
	if err != nil {
		return err
	}
	
	//unmarshal cip
	var children_invitation_pointer ChildInvitationPointer
	err = json.Unmarshal(unmarshaled_cip, &children_invitation_pointer)
	
	//check for error
	if err != nil {
		return err
	}
	
	//iterate though children
	for i := 0; i < len(children_invitation_pointer.ChildrenUUIDs); i ++ {	
		//get the child cip
		err = RevokeCipChildren(children_invitation_pointer.ChildrenKeys[i * 32: (i + 1) * 32], children_invitation_pointer.ChildrenUUIDs[i])
	
		//check for error
		if err != nil {
			return err
		}
	}
	
	//delete pip
	userlib.DatastoreDelete(children_invitation_pointer.PipUUID)
	
	//delete ip
	userlib.DatastoreDelete(children_invitation_pointer.IpUUID)
	
	//delete itself
	userlib.DatastoreDelete(cip_uuid)
	
	return nil
}

func StorePrivateContent(key_one []byte, key_two []byte, duuid uuid.UUID, content []byte) (error) {
	//encode container with first key
	encoded_content := userlib.SymEnc(key_one, userlib.RandomBytes(16), content)
	
	//mac container with second key
	maced_content, err := userlib.HMACEval(key_two, encoded_content)
	
	//check for error
	if err != nil {
		return err
	}
	
	//store the content
	userlib.DatastoreSet(duuid, append(maced_content, encoded_content...))
	
	return nil
}

func DecryptPrivateContent(key_one []byte, key_two []byte, duuid uuid.UUID) ([]byte, error) {
	//get user namespace data
	data, success := userlib.DatastoreGet(duuid)
	
	//check for error, or if could not find namespace
	if !success {
		return nil, errors.New("Could not find key value pair in datastore")
	}
	
	//make sure there are more than 64 bytes
	if (len(data) <= 64) {
		return nil, errors.New("data is not long enough")
	}
	
	//mac is first 64 bytes
	var data_mac []byte = data[0:64]
	
	//compute mac of remaning data
	computed_mac, err := userlib.HMACEval(key_two, data[64:])
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//verify mac for integrity and authenticity
	if (!userlib.HMACEqual(data_mac, computed_mac)) {
		return nil, errors.New("data mac and computed mac do not match for namespace")
	}
	
	//decrypt rest of data
	decrypted_content := userlib.SymDec(key_one, data[64:])
	
	return decrypted_content, nil
}

func ClimbUpInvitationPointerTreeGetOrigin(ip_keys_ []byte, ip_uuid_ uuid.UUID) (InvitationPointer, []byte, uuid.UUID, error) {
	//set loop values
	var ip_keys []byte = ip_keys_
	var ip_uuid uuid.UUID = ip_uuid_
	var unmarshaled_ip []byte
	var invitation_pointer InvitationPointer
	
	var err error
	
	//loop up the tree until either an break in the branch or the origin is found
	for true {
		//get ip data
		unmarshaled_ip, err = DecryptPrivateContent(ip_keys[0:16], ip_keys[16:32], ip_uuid)
		
		//check for error
		if err != nil {
			return invitation_pointer, nil, uuid.Nil, err
		}
		
		//unmarshal ip
		err = json.Unmarshal(unmarshaled_ip, &invitation_pointer)
		
		//check for error
		if err != nil {
			return invitation_pointer, nil, uuid.Nil, err
		}
		
		//if origin
		if invitation_pointer.IsOrigin {
			//set file keys and uuid
			return invitation_pointer, ip_keys, ip_uuid, nil
		} else {
			//set values for next iteration
			ip_keys = invitation_pointer.ParentKeys
			ip_uuid = invitation_pointer.ParentUUID
		}
	}
	
	return invitation_pointer, nil, uuid.Nil, errors.New("was not able to find origin")
}

func ClimbUpInvitationPointerTree(ip_keys_ []byte, ip_uuid_ uuid.UUID) ([]byte, uuid.UUID, error) {	
	//get origin
	var origin, _, _, err = ClimbUpInvitationPointerTreeGetOrigin(ip_keys_, ip_uuid_)

	//check for error
	if err != nil {
		return nil, uuid.Nil, err
	}
		
	//return file container keys and uuid
	return origin.ParentKeys, origin.ParentUUID, nil
}

func RemoveFileContents(file_keys []byte, file_uuid uuid.UUID) ([]byte, error) {
	//get the file container
	unmarshaled_file_container, err := DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_uuid)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//unmarshal file container
	var file_container FileContainer
	err = json.Unmarshal(unmarshaled_file_container, &file_container)
	
	//check for error
	if err != nil {
		return nil, err
	}
	
	//loop variables
	var file_link_uuid uuid.UUID = file_container.First
	var unmarshaled_file_link []byte
	var file_link FileLink
	var file_fragment_content []byte
	var content []byte
	
	for true {
		//get the file link
		unmarshaled_file_link, err = DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_link_uuid)
		
		//check for error
		if err != nil {
			return nil, err
		}
		
		//unmarshal file link
		err = json.Unmarshal(unmarshaled_file_link, &file_link)
	
		//check for error
		if err != nil {
			return nil, err
		}
		
		//get file fragment
		file_fragment_content, err = DecryptPrivateContent(file_keys[0:16], file_keys[16:32], file_link.FragmentUUID)
	
		//check for error
		if err != nil {
			return nil, err
		}
		
		//add fragment content to current content
		content = append(content, file_fragment_content...)
		
		//delete file fragment and link
		userlib.DatastoreDelete(file_link.FragmentUUID)
		userlib.DatastoreDelete(file_link_uuid)
		
		//if we have reached end of link chain
		if file_link.Next == uuid.Nil {
			break
		}

		//set next link uuid
		file_link_uuid = file_link.Next
	}
	
	//delete file container
	userlib.DatastoreDelete(file_uuid)
	
	//return file content
	return content, nil
}

func CreateFileContents(content []byte) ([]byte, uuid.UUID, error) {
	//create uuids
	var file_container_uuid = uuid.New()
	
	//create file container
	var file_container FileContainer
	
	//create keys
	var file_keys = append(userlib.RandomBytes(16), userlib.RandomBytes(16)...)
	
	//create uuids
	var file_fragment_uuid = uuid.New()
	var file_link_uuid = uuid.New()
	
	//store file fragment
	err := StorePrivateContent(file_keys[0:16], file_keys[16:32], file_fragment_uuid, content)
	
	//check for error
	if err != nil {
		return nil, uuid.Nil, err
	}
	
	//create file link
	var file_link FileLink
	
	file_link.FragmentUUID = file_fragment_uuid
	
	//marshal file link
	marshaled_fl, err := json.Marshal(&file_link)
	
	//check for error
	if err != nil {
		return nil, uuid.Nil, err
	}
	
	//store file link
	err = StorePrivateContent(file_keys[0:16],file_keys[16:32], file_link_uuid, marshaled_fl)
	
	//check for error
	if err != nil {
		return nil, uuid.Nil, err
	}
	
	file_container.First = file_link_uuid
	file_container.Last = file_link_uuid
		
	//marshal file container
	marshaled_file_container, err := json.Marshal(&file_container)
	
	//check for error
	if err != nil {
		return nil, uuid.Nil, err
	}
	
	//store file container
	err = StorePrivateContent(file_keys[0:16], file_keys[16:32], file_container_uuid, marshaled_file_container)
	
	//check for error
	if err != nil {
		return nil, uuid.Nil, err
	}
	
	//return keys and uuid
	return file_keys, file_container_uuid, nil
}