package ratchet

// This test suite validates the three ratchet types used in I2P's
// ECIES-X25519-AEAD-Ratchet: the session tag ratchet, the symmetric key
// ratchet, and the DH ratchet.
//
// The KDFs use HKDF-SHA256 (RFC 5869) with the spec's info strings, matching
// the I2P specification. See doc.go for the history of the earlier (non-spec)
// Signal-style HMAC construction that was corrected.

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/rand"
)

// TestTagRatchet verifies that the session tag ratchet produces a new,
// different tag on each Advance() call, and that the tag is the correct size.
func TestTagRatchet(t *testing.T) {
	t.Run("BasicTagGeneration", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewTagRatchet(chainKey)

		// Generate 10 tags and ensure they're unique
		tags := make(map[[SessionTagSize]byte]bool)
		for i := 0; i < 10; i++ {
			tag, err := ratchet.GenerateNextTag()
			if err != nil {
				t.Fatalf("failed to generate tag %d: %v", i, err)
			}

			if tags[tag] {
				t.Errorf("duplicate tag generated: %x", tag)
			}
			tags[tag] = true
		}

		if len(tags) != 10 {
			t.Errorf("expected 10 unique tags, got %d", len(tags))
		}
	})

	t.Run("PeekNextTag", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewTagRatchet(chainKey)

		// Peek should return the same tag multiple times
		tag1, err := ratchet.PeekNextTag()
		if err != nil {
			t.Fatalf("failed to peek tag: %v", err)
		}

		tag2, err := ratchet.PeekNextTag()
		if err != nil {
			t.Fatalf("failed to peek tag: %v", err)
		}

		if !bytes.Equal(tag1[:], tag2[:]) {
			t.Errorf("peek returned different tags")
		}

		// Generate should return the peeked tag
		tag3, err := ratchet.GenerateNextTag()
		if err != nil {
			t.Fatalf("failed to generate tag: %v", err)
		}

		if !bytes.Equal(tag1[:], tag3[:]) {
			t.Errorf("generated tag differs from peeked tag")
		}
	})

	t.Run("TagCount", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		ratchet := NewTagRatchet(chainKey)

		if ratchet.GetTagCount() != 0 {
			t.Errorf("initial tag count should be 0, got %d", ratchet.GetTagCount())
		}

		for i := 1; i <= 5; i++ {
			_, err := ratchet.GenerateNextTag()
			if err != nil {
				t.Fatalf("failed to generate tag: %v", err)
			}
			if ratchet.GetTagCount() != uint32(i) {
				t.Errorf("expected tag count %d, got %d", i, ratchet.GetTagCount())
			}
		}
	})

	t.Run("Zero", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewTagRatchet(chainKey)
		ratchet.Zero()

		// Verify chain key is zeroed
		zeroKey := [ChainKeySize]byte{}
		if !bytes.Equal(ratchet.chainKey[:], zeroKey[:]) {
			t.Errorf("chain key not zeroed")
		}
		if ratchet.tagCount != 0 {
			t.Errorf("tag count not zeroed")
		}
	})
}

// TestSymmetricRatchet verifies that the symmetric key ratchet derives a
// different message key and advances the chain key on each Advance() call.
func TestSymmetricRatchet(t *testing.T) {
	t.Run("MessageKeyDerivation", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewSymmetricRatchet(chainKey)

		// Per the I2P spec (section 4c), the message key is derived solely
		// from the chain key via HKDF; the message number is not part of the
		// KDF. So any message number yields the same key until Advance() is
		// called.
		key0, err := ratchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("failed to derive message key 0: %v", err)
		}

		key1, err := ratchet.DeriveMessageKey(1)
		if err != nil {
			t.Fatalf("failed to derive message key 1: %v", err)
		}

		// Same key regardless of message number (before advance).
		if !bytes.Equal(key0[:], key1[:]) {
			t.Errorf("message key should be independent of message number before advance")
		}

		// Advancing the ratchet must produce a different message key.
		if err := ratchet.Advance(); err != nil {
			t.Fatalf("failed to advance ratchet: %v", err)
		}
		keyAfter, err := ratchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("failed to derive message key after advance: %v", err)
		}
		if bytes.Equal(key0[:], keyAfter[:]) {
			t.Errorf("message key should change after advance")
		}
	})

	t.Run("Advance", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewSymmetricRatchet(chainKey)
		oldChainKey := ratchet.GetChainKey()

		if err := ratchet.Advance(); err != nil {
			t.Fatalf("failed to advance ratchet: %v", err)
		}

		newChainKey := ratchet.GetChainKey()

		if bytes.Equal(oldChainKey[:], newChainKey[:]) {
			t.Errorf("chain key should change after advance")
		}
	})

	t.Run("DeriveMessageKeyAndAdvance", func(t *testing.T) {
		var chainKey [ChainKeySize]byte
		if _, err := rand.Read(chainKey[:]); err != nil {
			t.Fatalf("failed to generate chain key: %v", err)
		}

		ratchet := NewSymmetricRatchet(chainKey)
		initialChainKey := ratchet.GetChainKey()

		messageKey, oldChainKey, err := ratchet.DeriveMessageKeyAndAdvance(0)
		if err != nil {
			t.Fatalf("failed to derive and advance: %v", err)
		}

		// Old chain key should match initial
		if !bytes.Equal(oldChainKey[:], initialChainKey[:]) {
			t.Errorf("returned old chain key doesn't match initial")
		}

		// Chain key should have advanced
		newChainKey := ratchet.GetChainKey()
		if bytes.Equal(newChainKey[:], initialChainKey[:]) {
			t.Errorf("chain key should have advanced")
		}

		// Message key should be non-zero
		zeroKey := [MessageKeySize]byte{}
		if bytes.Equal(messageKey[:], zeroKey[:]) {
			t.Errorf("message key should be non-zero")
		}
	})
}

// TestDHRatchet verifies that the DH ratchet advances the chain key when a new
// DH shared secret is mixed in, producing a different key each time.
func TestDHRatchet(t *testing.T) {
	t.Run("PerformRatchet", func(t *testing.T) {
		// Generate two key pairs
		var rootKey, privKey1 [ChainKeySize]byte
		var pubKey2 [PublicKeySize]byte

		if _, err := rand.Read(rootKey[:]); err != nil {
			t.Fatalf("failed to generate root key: %v", err)
		}
		if _, err := rand.Read(privKey1[:]); err != nil {
			t.Fatalf("failed to generate private key 1: %v", err)
		}
		if _, err := rand.Read(pubKey2[:]); err != nil {
			t.Fatalf("failed to generate public key 2: %v", err)
		}

		ratchet := NewDHRatchet(rootKey, privKey1, pubKey2)

		oldRootKey := ratchet.rootKey
		nextRootKey, ck, err := ratchet.PerformRatchet()
		if err != nil {
			t.Fatalf("failed to perform DH ratchet: %v", err)
		}

		// nextRootKey is the updated root key for the next ratchet step; ck is
		// the chain key output of DH_INITIALIZE. They are distinct values.
		// The caller applies the TagAndKeyGenKeys KDF to ck to obtain the
		// session tag and symmetric chain keys.

		// Keys should be non-zero
		zeroKey := [ChainKeySize]byte{}
		if bytes.Equal(nextRootKey[:], zeroKey[:]) {
			t.Errorf("next root key should be non-zero")
		}
		if bytes.Equal(ck[:], zeroKey[:]) {
			t.Errorf("ck should be non-zero")
		}

		// The root key should have advanced (nextRootKey != old rootKey).
		if bytes.Equal(ratchet.rootKey[:], oldRootKey[:]) {
			t.Errorf("root key should have advanced after ratchet")
		}
		// The returned nextRootKey should match the ratchet's internal root key.
		if !bytes.Equal(nextRootKey[:], ratchet.rootKey[:]) {
			t.Errorf("returned nextRootKey should match internal root key")
		}
	})

	t.Run("UpdateKeys", func(t *testing.T) {
		var rootKey, privKey, oldPubKey [ChainKeySize]byte
		if _, err := rand.Read(rootKey[:]); err != nil {
			t.Fatalf("failed to generate root key: %v", err)
		}

		ratchet := NewDHRatchet(rootKey, privKey, oldPubKey)

		newPubKey := make([]byte, PublicKeySize)
		if _, err := rand.Read(newPubKey); err != nil {
			t.Fatalf("failed to generate new public key: %v", err)
		}

		if err := ratchet.UpdateKeys(newPubKey); err != nil {
			t.Fatalf("failed to update keys: %v", err)
		}

		if !bytes.Equal(ratchet.theirPubKey[:], newPubKey) {
			t.Errorf("public key not updated correctly")
		}
	})

	t.Run("GenerateNewKeyPair", func(t *testing.T) {
		var rootKey, privKey, pubKey [ChainKeySize]byte
		ratchet := NewDHRatchet(rootKey, privKey, pubKey)

		newPubKey, err := ratchet.GenerateNewKeyPair()
		if err != nil {
			t.Fatalf("failed to generate new key pair: %v", err)
		}

		// New public key should be non-zero
		zeroKey := [PublicKeySize]byte{}
		if bytes.Equal(newPubKey[:], zeroKey[:]) {
			t.Errorf("generated public key should be non-zero")
		}
	})
}

// TestRatchetSymmetricKey verifies that RatchetSymmetricKey derives a message
// key and a new chain key that both differ from the input chain key and from
// each other.
func TestRatchetSymmetricKey(t *testing.T) {
	var chainKey [ChainKeySize]byte
	if _, err := rand.Read(chainKey[:]); err != nil {
		t.Fatalf("failed to generate chain key: %v", err)
	}

	messageKey, newChainKey, err := RatchetSymmetricKey(chainKey, 0)
	if err != nil {
		t.Fatalf("RatchetSymmetricKey failed: %v", err)
	}

	// Keys should be different
	if bytes.Equal(messageKey[:], newChainKey[:]) {
		t.Errorf("message key and new chain key should differ")
	}

	// Keys should differ from original chain key
	if bytes.Equal(messageKey[:], chainKey[:]) {
		t.Errorf("message key should differ from chain key")
	}
	if bytes.Equal(newChainKey[:], chainKey[:]) {
		t.Errorf("new chain key should differ from old chain key")
	}
}

// BenchmarkTagRatchet benchmarks tag generation
func BenchmarkTagRatchet(b *testing.B) {
	var chainKey [ChainKeySize]byte
	rand.Read(chainKey[:])
	ratchet := NewTagRatchet(chainKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ratchet.GenerateNextTag()
	}
}

// BenchmarkSymmetricRatchet benchmarks message key derivation
func BenchmarkSymmetricRatchet(b *testing.B) {
	var chainKey [ChainKeySize]byte
	rand.Read(chainKey[:])
	ratchet := NewSymmetricRatchet(chainKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ratchet.DeriveMessageKey(uint32(i))
	}
}

// BenchmarkDHRatchet benchmarks DH ratchet operations
func BenchmarkDHRatchet(b *testing.B) {
	var rootKey, privKey, pubKey [ChainKeySize]byte
	rand.Read(rootKey[:])
	rand.Read(privKey[:])
	rand.Read(pubKey[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ratchet := NewDHRatchet(rootKey, privKey, pubKey)
		_, _, _ = ratchet.PerformRatchet()
	}
}

// TestZeroValueFootguns demonstrates why direct construction is dangerous
func TestZeroValueFootguns(t *testing.T) {
	t.Run("DHRatchet zero-value is cryptographically invalid", func(t *testing.T) {
		// WRONG: Direct construction with zero values
		var badRatchet DHRatchet

		// This will produce weak/invalid keys because all internal state is zero
		nextRootKey, ck, err := badRatchet.PerformRatchet()
		if err != nil {
			t.Logf("Expected behavior: DH ratchet with zero keys fails: %v", err)
		}

		// Even if it succeeds, the keys will be derived from all-zero state
		zeroKey := [ChainKeySize]byte{}
		if bytes.Equal(nextRootKey[:], zeroKey[:]) && bytes.Equal(ck[:], zeroKey[:]) {
			t.Log("Zero-value DHRatchet produces zero keys - cryptographically invalid!")
		}

		// CORRECT: Always use constructor
		var rootKey, privKey, pubKey [ChainKeySize]byte
		rand.Read(rootKey[:])
		rand.Read(privKey[:])
		rand.Read(pubKey[:])
		goodRatchet := NewDHRatchet(rootKey, privKey, pubKey)

		sendKeyGood, _, err := goodRatchet.PerformRatchet()
		if err != nil {
			t.Fatalf("Constructor-initialized ratchet should work: %v", err)
		}
		if bytes.Equal(sendKeyGood[:], zeroKey[:]) {
			t.Error("Properly initialized ratchet produced zero keys - unexpected!")
		}
	})

	t.Run("SymmetricRatchet zero-value produces predictable keys", func(t *testing.T) {
		// WRONG: Direct construction with zero chain key
		var badRatchet SymmetricRatchet

		// Keys will be derived from all-zero chain key - predictable and weak
		key1, err := badRatchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("DeriveMessageKey failed: %v", err)
		}

		// Create another zero-value ratchet
		var badRatchet2 SymmetricRatchet
		key2, err := badRatchet2.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("DeriveMessageKey failed: %v", err)
		}

		// They produce identical keys - no randomness!
		if bytes.Equal(key1[:], key2[:]) {
			t.Log("Zero-value SymmetricRatchet produces identical keys - cryptographically invalid!")
		}

		// CORRECT: Always use constructor with random chain key
		var chainKey [ChainKeySize]byte
		rand.Read(chainKey[:])
		goodRatchet := NewSymmetricRatchet(chainKey)

		keyGood, err := goodRatchet.DeriveMessageKey(0)
		if err != nil {
			t.Fatalf("Constructor-initialized ratchet should work: %v", err)
		}

		// Should differ from zero-state keys
		if bytes.Equal(keyGood[:], key1[:]) {
			t.Error("Properly initialized ratchet produced same key as zero-state - unexpected!")
		}
	})

	t.Run("TagRatchet zero-value produces predictable tags", func(t *testing.T) {
		// WRONG: Direct construction with zero chain key
		var badRatchet TagRatchet

		// Tags will be derived from all-zero chain key - predictable
		tag1, err := badRatchet.GenerateNextTag()
		if err != nil {
			t.Fatalf("GenerateNextTag failed: %v", err)
		}

		// Create another zero-value ratchet
		var badRatchet2 TagRatchet
		tag2, err := badRatchet2.GenerateNextTag()
		if err != nil {
			t.Fatalf("GenerateNextTag failed: %v", err)
		}

		// They produce identical tags - no randomness!
		if bytes.Equal(tag1[:], tag2[:]) {
			t.Log("Zero-value TagRatchet produces identical tags - cryptographically invalid!")
		}

		// CORRECT: Always use constructor with random chain key
		var chainKey [ChainKeySize]byte
		rand.Read(chainKey[:])
		goodRatchet := NewTagRatchet(chainKey)

		tagGood, err := goodRatchet.GenerateNextTag()
		if err != nil {
			t.Fatalf("Constructor-initialized ratchet should work: %v", err)
		}

		// Should differ from zero-state tags
		if bytes.Equal(tagGood[:], tag1[:]) {
			t.Error("Properly initialized ratchet produced same tag as zero-state - unexpected!")
		}
	})
}

// TestSessionTagsetLimit verifies that a Session enforces the spec's tag-set
// message-number cap: since 65535 is a valid message number, the first 65536
// messages (numbers 0..65535) succeed and the next one returns
// ErrTagsetExhausted, forcing a DH ratchet step.
func TestSessionTagsetLimit(t *testing.T) {
	var sharedSecret, ourPriv, theirPub [32]byte
	rand.Read(sharedSecret[:])
	rand.Read(ourPriv[:])
	rand.Read(theirPub[:])

	session, err := NewSessionFromECIES(sharedSecret, ourPriv, theirPub)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Spec §3 makes 65535 a valid message number, so numbers 0..65535
	// (MaxMessagesPerTagset+1 messages) must all succeed.
	for i := 0; i <= MaxMessagesPerTagset; i++ {
		if _, _, _, err := session.EncryptMessage([]byte("m")); err != nil {
			t.Fatalf("message %d failed unexpectedly: %v", i, err)
		}
	}

	// The next message (number 65536) must fail with ErrTagsetExhausted.
	// oops.OopsError is not comparable, so compare by message.
	if _, _, _, err := session.EncryptMessage([]byte("m")); err == nil || err.Error() != ErrTagsetExhausted.Error() {
		t.Fatalf("expected ErrTagsetExhausted after %d messages, got: %v", MaxMessagesPerTagset+1, err)
	}

	// A DH ratchet step must reset the message counter and allow encryption
	// to resume.
	if _, _, err := session.PerformDHRatchet(); err != nil {
		t.Fatalf("DH ratchet failed: %v", err)
	}
	if session.GetMessageNumber() != 0 {
		t.Fatalf("expected message number to reset to 0 after DH ratchet, got %d", session.GetMessageNumber())
	}
	if _, _, _, err := session.EncryptMessage([]byte("m")); err != nil {
		t.Fatalf("encryption after DH ratchet failed: %v", err)
	}
}

// TestSessionTagAndKeyGenKeys verifies that NewSessionFromECIES runs the
// spec's mandatory Noise Split() on the DH INITIALIZATION chain key and then
// splits each direction's key via the TagAndKeyGenKeys KDF into the session tag
// chain key and the symmetric key chain key, and that the resulting ratchets
// match an independent derivation.
func TestSessionTagAndKeyGenKeys(t *testing.T) {
	var sharedSecret, ourPriv, theirPub [32]byte
	rand.Read(sharedSecret[:])
	rand.Read(ourPriv[:])
	rand.Read(theirPub[:])

	// Independent derivation of the expected chain keys: the spec's mandatory
	// Noise Split() on the handshake chaining key, then DH_INITIALIZE for the
	// initiator's outbound direction, then TagAndKeyGenKeys.
	rootKey := sharedSecret
	k1, _, err := Split(rootKey)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}
	nextRootKey, ck, err := DH_INITIALIZEFull(rootKey, k1)
	if err != nil {
		t.Fatalf("DH_INITIALIZEFull failed: %v", err)
	}
	keydata, err := kdf.StandardHKDF(ck[:], nil, []byte("TagAndKeyGenKeys"), 64)
	if err != nil {
		t.Fatalf("TagAndKeyGenKeys KDF failed: %v", err)
	}
	var sessTagCK, symmKeyCK [ChainKeySize]byte
	copy(sessTagCK[:], keydata[0:32])
	copy(symmKeyCK[:], keydata[32:64])

	// The session must produce the same next tag and first message key.
	session, err := NewSessionFromECIES(sharedSecret, ourPriv, theirPub)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	wantTag, err := NewTagRatchet(sessTagCK).PeekNextTag()
	if err != nil {
		t.Fatalf("expected tag derivation failed: %v", err)
	}
	gotTag, err := session.GetNextTag()
	if err != nil {
		t.Fatalf("GetNextTag failed: %v", err)
	}
	if gotTag != wantTag {
		t.Errorf("session tag mismatch:\n got  %x\n want %x", gotTag, wantTag)
	}

	wantKey, err := NewSymmetricRatchet(symmKeyCK).DeriveMessageKey(0)
	if err != nil {
		t.Fatalf("expected key derivation failed: %v", err)
	}
	gotKey, _, _, err := session.EncryptMessage([]byte("m"))
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}
	if gotKey != wantKey {
		t.Errorf("message key mismatch:\n got  %x\n want %x", gotKey, wantKey)
	}

	// The initial sending root key must equal the DH INITIALIZATION output.
	if session.sendingRootKey != nextRootKey {
		t.Errorf("initial sending root key mismatch:\n got  %x\n want %x", session.sendingRootKey, nextRootKey)
	}

	// A DH ratchet step must succeed and produce a non-zero chain key.
	dhCK, _, err := session.PerformDHRatchet()
	if err != nil {
		t.Fatalf("PerformDHRatchet failed: %v", err)
	}
	if dhCK == [32]byte{} {
		t.Error("DH ratchet produced a zero chain key - unexpected")
	}
}

// TestSessionDirectionsIndependent is a regression test for the spec's
// mandatory Noise Split() (section 4a: "Bob and Alice must run the Noise
// Split() function on the resulting CipherState to create independent symmetric
// and tag chain keys for inbound and outbound sessions").
//
// An earlier implementation assigned the same chain key to both directions, so
// outbound and inbound messages drew tags, message keys and nonces from a single
// shared chain. Two effects of that bug were observable: a session's first
// outbound tag equalled the first tag it expected to receive (so the two
// directions could not be told apart), and two peers created from the same key
// material with the same role produced identical streams.
func TestSessionDirectionsIndependent(t *testing.T) {
	var sharedSecret, ourPriv, theirPub [32]byte
	rand.Read(sharedSecret[:])
	rand.Read(ourPriv[:])
	rand.Read(theirPub[:])

	session, err := NewSessionFromECIES(sharedSecret, ourPriv, theirPub)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Zero()

	outTag, err := session.GetNextTag()
	if err != nil {
		t.Fatalf("GetNextTag failed: %v", err)
	}
	inTag, err := session.GetReceivingNextTag()
	if err != nil {
		t.Fatalf("GetReceivingNextTag failed: %v", err)
	}
	if outTag == inTag {
		t.Errorf("outbound and inbound tag chains are identical (%x) - Split() missing", outTag)
	}

	// The two directions must also derive different message keys. Each
	// direction has its own counter starting at zero, so the nonces coincide by
	// design - what matters is that the keys differ, which is what makes the
	// shared-counter bug harmless to fix rather than a wire-format change.
	outKey, _, _, err := session.EncryptMessage([]byte("m"))
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}
	inKey, _, err := session.DecryptMessage(inTag)
	if err != nil {
		t.Fatalf("DecryptMessage failed: %v", err)
	}
	if outKey == inKey {
		t.Error("outbound and inbound derived the same message key - chains are not independent")
	}

	// A peer created with the opposite role must send on this session's inbound
	// chain and receive on its outbound chain, so the two can talk.
	peer, err := NewSessionFromECIESWithRole(sharedSecret, theirPub, ourPriv, RoleResponder)
	if err != nil {
		t.Fatalf("failed to create peer session: %v", err)
	}
	defer peer.Zero()

	peerFirstTag, err := peer.GetNextTag()
	if err != nil {
		t.Fatalf("peer GetNextTag failed: %v", err)
	}
	if peerFirstTag != inTag {
		t.Errorf("peer outbound tag %x does not match our inbound tag %x", peerFirstTag, inTag)
	}
	if peerFirstTag == outTag {
		t.Error("peer outbound tag collides with our outbound tag - roles not separated")
	}
}

// TestSessionOutOfOrderDelivery is a regression test for the receiver's
// look-ahead window. The tag and symmetric key ratchets are synchronized, so a
// tag matched at offset i must yield the message key derived at that same
// position - not the key at the receiver's current position. An earlier
// implementation advanced only the tag ratchet, silently returning the wrong key
// for out-of-order messages (and then rejecting the skipped ones).
func TestSessionOutOfOrderDelivery(t *testing.T) {
	var ss, ourPriv, theirPub [32]byte
	for i := range ss {
		ss[i] = byte(i + 1)
		ourPriv[i] = byte(i + 7)
		theirPub[i] = byte(i + 13)
	}

	sender, err := NewSessionFromECIES(ss, ourPriv, theirPub)
	if err != nil {
		t.Fatalf("sender: %v", err)
	}

	const n = 5
	type msg struct {
		tag   [SessionTagSize]byte
		key   [MessageKeySize]byte
		nonce [NonceSize]byte
	}
	sent := make([]msg, n)
	for i := 0; i < n; i++ {
		k, tag, nonce, err := sender.EncryptMessage([]byte("payload"))
		if err != nil {
			t.Fatalf("EncryptMessage %d: %v", i, err)
		}
		sent[i] = msg{tag: tag, key: k, nonce: nonce}
	}

	// The receiver is the responder: with the mandatory Noise Split() the two
	// directions use different halves of the split output, so a peer only sees
	// the sender's outbound chain if it is given the opposite role.
	receiver, err := NewSessionFromECIESWithRole(ss, theirPub, ourPriv, RoleResponder)
	if err != nil {
		t.Fatalf("receiver: %v", err)
	}

	// Deliver in an order that forces out-of-order handling: newest first, then
	// the skipped earlier messages.
	order := []int{4, 2, 0, 1, 3}
	got := make(map[int]bool)
	for _, i := range order {
		key, nonce, err := receiver.DecryptMessage(sent[i].tag)
		if err != nil {
			t.Fatalf("DecryptMessage(tag[%d]): %v", i, err)
		}
		if key != sent[i].key {
			t.Errorf("message %d: wrong key\n got  %x\n want %x", i, key, sent[i].key)
		}
		// The nonce must be the message's own number, so the caller can actually
		// open an out-of-order ciphertext.
		if nonce != sent[i].nonce {
			t.Errorf("message %d: wrong nonce got %x want %x", i, nonce, sent[i].nonce)
		}
		got[i] = true
	}
	if len(got) != n {
		t.Errorf("expected %d distinct messages, got %d", n, len(got))
	}

	// Replaying an already-consumed tag must be rejected.
	if _, _, err := receiver.DecryptMessage(sent[0].tag); err == nil {
		t.Error("replayed tag should be rejected")
	}

	// A tag outside the window must be rejected.
	if _, _, err := receiver.DecryptMessage([SessionTagSize]byte{1, 2, 3, 4, 5, 6, 7, 8}); err == nil {
		t.Error("unknown tag should be rejected")
	}
}

// TestSplitKnownAnswer checks the Noise Split() implementation against vectors
// computed independently from the Noise specification's definition:
//
//	temp_hk = HKDF(ck, zerolen, "", 64)
//	temp_k1 = temp_hk[0:32]
//	temp_k2 = temp_hk[32:64]
//
// with ck = 0x01..0x20. The I2P ECIES spec imports this function by name
// (section 4a: "must run the Noise Split() function"), so the derivation must
// match Noise exactly rather than merely be self-consistent.
func TestSplitKnownAnswer(t *testing.T) {
	var ck [ChainKeySize]byte
	for i := range ck {
		ck[i] = byte(i + 1)
	}

	k1, k2, err := Split(ck)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	wantK1 := "fc5eccc8a17f5575645b191c4123bcec6defa32c721a6c5009f4c251bc39c309"
	wantK2 := "46685175eb3b43cc7858098eaed45a5c9b6c967cca8c26dbf23f98bbeab77538"
	if got := hex.EncodeToString(k1[:]); got != wantK1 {
		t.Errorf("Split k1 mismatch:\n got  %s\n want %s", got, wantK1)
	}
	if got := hex.EncodeToString(k2[:]); got != wantK2 {
		t.Errorf("Split k2 mismatch:\n got  %s\n want %s", got, wantK2)
	}
	if k1 == k2 {
		t.Error("Split returned identical keys for the two directions")
	}
}
