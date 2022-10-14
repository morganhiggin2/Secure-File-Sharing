package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

const aUsername = "v0sc0k"
const bUsername = "vpo988d"
const cUsername = "0"

const aPassword = "apassword"
const bPassword = "bp-as*Sword"
const cPassword = ""

const aFileName = "a.txt"
const bFileName = "b.txt"
const cFileName = "a.txt"

const fileFragmentOne = "this is the first of"
const fileFragmentTwo = " the great and late"
const fileFragmentThree = " americans!!!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User
	var aSessionOne *client.User
	//var aSessionTwo *client.User
	var bSessionOne *client.User
	//var bSessionTwo *client.User
	var cSessionOne *client.User
	//var cSessionTwo *client.User	

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Trying initializing user Alice again.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).NotTo(BeNil())
			
			userlib.DebugMsg("Trying initializing empty user")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).NotTo(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
	})
	
	Describe("Custom Tests", func() {

		Specify("Custom Test: Creating and Getting Users with the same names.", func() {
			userlib.DebugMsg("Initializing user a")
			aSessionOne, err = client.InitUser(aUsername, aPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Initializing user a again")
			aSessionOne, err = client.InitUser(aUsername, aPassword)
			Expect(err).NotTo(BeNil())
			
			userlib.DebugMsg("Initializing user b")
			bSessionOne, err = client.InitUser(bUsername, bPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Getting user a")
			aSessionOne, err = client.GetUser(aUsername, aPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user a with wrong password.")
			aSessionOne, err = client.GetUser(aUsername, bPassword)
			Expect(err).NotTo(BeNil())
			
			userlib.DebugMsg("Getting user b with wrong password.")
			bSessionOne, err = client.GetUser(bUsername, cPassword)
			Expect(err).NotTo(BeNil())
			
			userlib.DebugMsg("Getting user c that does not exist")
			cSessionOne, err = client.GetUser(cUsername, cPassword)
			Expect(err).NotTo(BeNil())
			
			userlib.DebugMsg("Getting user b")
			bSessionOne, err = client.GetUser(bUsername, bPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Getting user a")
			aSessionOne, err = client.GetUser(aUsername, aPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Getting user a with wrong password")
			aSessionOne, err = client.GetUser(aUsername, cPassword)
			Expect(err).NotTo(BeNil())
			
			userlib.DebugMsg("Getting user b with wrong password")
			bSessionOne, err = client.GetUser(bUsername, cPassword)
			Expect(err).NotTo(BeNil())
		})

		Specify("Custom Test: Create File Structure and Sharing", func() {
			userlib.DebugMsg("Initializing user a")
			aSessionOne, err = client.InitUser(aUsername, aPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Initializing user b")
			bSessionOne, err = client.InitUser(bUsername, bPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Initializing user c")
			cSessionOne, err = client.InitUser(cUsername, cPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("User a store file a")
			aSessionOne.StoreFile(aFileName, []byte(fileFragmentOne))

			userlib.DebugMsg("User a store file b")
			aSessionOne.StoreFile(bFileName, []byte(fileFragmentTwo))
			
			userlib.DebugMsg("User a loads file a")
			data, err := aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User b attempts to load file a, but can't")
			data, err = bSessionOne.LoadFile(aFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User a creates invitatioun for user b for file a")
			invite, err := aSessionOne.CreateInvitation(aFileName, bUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b accepts the invitation from user a for file a")
			err = bSessionOne.AcceptInvitation(aUsername, invite, bFileName)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b loads file b")
			data, err = bSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User b attempts to load file a, but can't")
			data, err = bSessionOne.LoadFile(aFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne)))

			userlib.DebugMsg("User b creates invitatioun for user c for file b")
			invite2, err := bSessionOne.CreateInvitation(bFileName, cUsername)
			Expect(err).To(BeNil())

			userlib.DebugMsg("User c attempts to load file b, but can't")
			data, err = cSessionOne.LoadFile(bFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User c store file b")
			cSessionOne.StoreFile(bFileName, []byte(fileFragmentTwo))
			
			userlib.DebugMsg("User c accepts the invitation from user b for file b")
			err = cSessionOne.AcceptInvitation(bUsername, invite2, cFileName)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User c loads file c")
			data, err = cSessionOne.LoadFile(cFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User b revokes User c's access from file b")
			err = bSessionOne.RevokeAccess(bFileName, cUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b attempts to revoke User a's access from file b")
			err = bSessionOne.RevokeAccess(bFileName, aUsername)
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("User c attempts to load file c, but can't")
			data, err = cSessionOne.LoadFile(cFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User b loads file b")
			data, err = bSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))

			userlib.DebugMsg("User a revokes User b's access from file a")
			err = aSessionOne.RevokeAccess(aFileName, bUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b attempts to load file b, but can't")
			data, err = bSessionOne.LoadFile(bFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User a loads file a")
			data, err = aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User a loads file b")
			data, err = aSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentTwo)))
			
			userlib.DebugMsg("User c loads file b")
			data, err = cSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentTwo)))
		})
		
		Specify("Custom Test: Appending to a file with multiple files", func() {
			userlib.DebugMsg("Initializing user a")
			aSessionOne, err = client.InitUser(aUsername, aPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("User a store file a")
			aSessionOne.StoreFile(aFileName, []byte(fileFragmentOne))
			
			userlib.DebugMsg("User a appending to file a")
			err = aSessionOne.AppendToFile(aFileName, []byte(fileFragmentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("User a store file b")
			aSessionOne.StoreFile(bFileName, []byte(fileFragmentOne))
			
			userlib.DebugMsg("User a appending to file b")
			err = aSessionOne.AppendToFile(bFileName, []byte(fileFragmentThree))
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User a loads file b")
			data, err := aSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne + fileFragmentThree)))
			
			userlib.DebugMsg("User a loads file a")
			data, err = aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne + fileFragmentTwo)))
			
			userlib.DebugMsg("User a store file a")
			aSessionOne.StoreFile(aFileName, []byte(fileFragmentThree))
			
			userlib.DebugMsg("User a loads file a")
			data, err = aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentThree)))
		})
		
		Specify("Custom Test: Appending to a file as recipient", func() {
			userlib.DebugMsg("Initializing user a")
			aSessionOne, err = client.InitUser(aUsername, aPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Initializing user b")
			bSessionOne, err = client.InitUser(bUsername, bPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("User a store file a")
			aSessionOne.StoreFile(aFileName, []byte(fileFragmentOne))
			
			userlib.DebugMsg("User a creates invitatioun for user b for file a")
			invite, err := aSessionOne.CreateInvitation(aFileName, bUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b accepts the invitation from user a for file a")
			err = bSessionOne.AcceptInvitation(aUsername, invite, bFileName)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b appending to file b")
			err = bSessionOne.AppendToFile(bFileName, []byte(fileFragmentTwo))
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b loads file b")
			data, err := bSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne + fileFragmentTwo)))
			
			userlib.DebugMsg("User a loads file a")
			data, err = aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne + fileFragmentTwo)))
			
			userlib.DebugMsg("User a appending to file a")
			err = aSessionOne.AppendToFile(aFileName, []byte(fileFragmentThree))
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b loads file b")
			data, err = bSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne + fileFragmentTwo + fileFragmentThree)))
			
			userlib.DebugMsg("User a loads file a")
			data, err = aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne + fileFragmentTwo + fileFragmentThree)))
		})
		
		Specify("Custom Test: Load a file that does not exist", func() {
			userlib.DebugMsg("Initializing user a")
			aSessionOne, err = client.InitUser(aUsername, aPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User a loads file a")
			data, err := aSessionOne.LoadFile(aFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne + fileFragmentTwo + fileFragmentThree)))
		})
		
		Specify("Custom Test: Create File Structure and Sharing", func() {
			userlib.DebugMsg("Initializing user a")
			aSessionOne, err = client.InitUser(aUsername, aPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Initializing user b")
			bSessionOne, err = client.InitUser(bUsername, bPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("Initializing user c")
			cSessionOne, err = client.InitUser(cUsername, cPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("User a store file a")
			aSessionOne.StoreFile(aFileName, []byte(fileFragmentOne))
			
			userlib.DebugMsg("User a loads file a")
			data, err := aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User a creates invitatioun for user b for file a")
			invite, err := aSessionOne.CreateInvitation(aFileName, bUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b accepts the invitation from user a for file a")
			err = bSessionOne.AcceptInvitation(aUsername, invite, bFileName)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b creates invitatioun for user c for file b")
			invite, err = bSessionOne.CreateInvitation(bFileName, cUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User c accepts the invitation from user b for file b")
			err = cSessionOne.AcceptInvitation(bUsername, invite, cFileName)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b loads file b")
			data, err = bSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User a revokes User c's access from file a")
			err = aSessionOne.RevokeAccess(aFileName, cUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User c attempts to load file c, but can't")
			data, err = cSessionOne.LoadFile(cFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne)))

			userlib.DebugMsg("User b loads file b")
			data, err = bSessionOne.LoadFile(bFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))

			userlib.DebugMsg("User a loads file a")
			data, err = aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
			
			userlib.DebugMsg("User a revokes User b's access from file a")
			err = aSessionOne.RevokeAccess(aFileName, bUsername)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("User b attempts to load file b, but can't")
			data, err = bSessionOne.LoadFile(bFileName)
			Expect(err).NotTo(BeNil())
			Expect(data).NotTo(Equal([]byte(fileFragmentOne)))

			userlib.DebugMsg("User a loads file a")
			data, err = aSessionOne.LoadFile(aFileName)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(fileFragmentOne)))
		})
	})
})
