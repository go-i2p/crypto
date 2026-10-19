package ratchet

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Role identifies which side of a session a local endpoint is, so that the two
// directions get the correct halves of the Noise Split() output.
//
// The spec assigns the two Split() keys by handshake role (section 4a: the
// split creates "independent symmetric and tag chain keys for inbound and
// outbound sessions"; Noise orders them so the handshake initiator uses the
// first key for sending and the responder uses the second). Because the two
// peers must disagree on the role, both endpoints cannot use the zero value:
// construct the responder with [RoleResponder].
type Role uint8

const (
	// RoleInitiator is the side that opened the session (sent the New Session
	// message). It sends on the first Split() key and receives on the second.
	RoleInitiator Role = 0
	// RoleResponder is the side that accepted the session (sent the New Session
	// Reply). It sends on the second Split() key and receives on the first.
	RoleResponder Role = 1
)

// Session combines DH ratchet, symmetric ratchet, and tag ratchet into a single
// coherent unit for ECIES-X25519-AEAD-Ratchet protocol. This provides a unified
// API for I2P garlic message encryption with forward secrecy.
//
// The Session handles:
//   - DH ratchet for periodic key agreement
//   - Symmetric ratchet for deriving message encryption keys
//   - Tag ratchet for session tag generation
//
// Per the I2P ECIES spec (section 4a), the ratchets are bidirectional and each
// direction is independent: after the handshake chain key is obtained, the
// mandatory Noise Split() produces two separate CipherState keys, and each
// direction keeps its own symmetric ratchet, tag ratchet, message counter and
// look-ahead window. A ratchet "is for a single direction... To generate keys
// for both directions, you have to ratchet twice", so each direction also keeps
// its own root key for the next DH ratchet step.
type Session struct {
	dhRatchet *DHRatchet

	// sending is the outbound direction's ratchet state.
	sending direction
	// receiving is the inbound direction's ratchet state.
	receiving direction

	// role selects which half of the Split() output this endpoint sends on.
	role Role

	// sendingRootKey is the root key for the sending direction, used as the
	// input to DH_INITIALIZE on the next DH ratchet step.
	sendingRootKey [ChainKeySize]byte
	// receivingRootKey is the root key for the receiving direction, used as the
	// input to DH_INITIALIZE by PerformReceivingDHRatchet.
	receivingRootKey [ChainKeySize]byte

	// lookaheadSize is the receiver look-ahead window size for session tag
	// validation (spec section 4b: "N might be at most 128, but 32 or even
	// less may be a better choice"). Defaults to DefaultLookaheadWindow.
	lookaheadSize int
}

// direction is one half of a Session: the ratchet state for a single direction
// of traffic, as spec section 4a requires ("a ratchet is for a single
// direction"). The two directions never share a chain key, a tag chain, or a
// message-number counter.
type direction struct {
	symRatchet *SymmetricRatchet
	tagRatchet *TagRatchet
	messageNum uint32

	// lookahead holds the pre-computed window of (session tag, message key)
	// pairs for out-of-order delivery tolerance, as required by spec sections
	// 4b and 4c: the receiver ratchets its tag chain ahead by the window size,
	// and because the session tag ratchet is synchronized with the symmetric
	// key ratchet, each tag is paired with the message key derived at the same
	// position. Index i is the entry at offset i from the current ratchet
	// position. Rebuilt after each successful verification and DH ratchet.
	lookahead []lookaheadEntry
}

// lookaheadEntry is one slot of the receiver's look-ahead window: the session
// tag on the wire, paired with the message key derived at the same ratchet
// position and the message number N for that slot. Advancing both chains
// together keeps the tag and symmetric key ratchets synchronized, as spec
// sections 4b and 4c require.
//
// N is stored alongside each tag because the spec makes the message number the
// ChaCha20-Poly1305 nonce: "n = The message number N in the current chain, as
// retrieved from the associated Session Tag" (section 1h). Without it a
// receiver could not rebuild the nonce for an out-of-order message.
type lookaheadEntry struct {
	tag  [SessionTagSize]byte
	key  [MessageKeySize]byte
	num  uint32
	used bool
}

// DataNonce builds the Existing Session AEAD nonce from a message number, per
// the I2P ECIES spec section 3: a 12-byte counter nonce whose first four bytes
// are always zero and whose last eight bytes are the message number n in
// little-endian order.
//
// The spec caps n at 65535 ("Higher values must never be used"); callers should
// enforce that through the tag-set limit rather than relying on this function.
func DataNonce(n uint32) [NonceSize]byte {
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(n))
	return nonce
}

// HandshakeResult contains the output of an ECIES key exchange handshake
type HandshakeResult struct {
	SharedSecret [32]byte // The ECIES-X25519 shared secret
	OurPrivKey   [32]byte // Our ephemeral private key
	TheirPubKey  [32]byte // Their public key
}

// NewSessionFromECIES creates a new session initialized from an ECIES shared
// secret, with the local endpoint as the handshake initiator. It is equivalent
// to [NewSessionFromECIESWithRole] with [RoleInitiator]; use the latter when
// both endpoints of a session are created in the same process, since the two
// peers must be given opposite roles.
//
// The shared secret stands in for the handshake chaining key. The spec's
// mandatory Noise Split() produces one key per direction, and each direction is
// then initialized independently through the DH INITIALIZATION KDF (section 4):
//
//	[k1, k2] = Split(rootKey)                    // section 4a, Noise split
//	k        = k1 outbound, k2 inbound (swapped for the responder)
//	keydata  = HKDF(salt=rootKey, ikm=k, info="KDFDHRatchetStep", 64)
//	nextRootKey = keydata[0:32]
//	ck          = keydata[32:64]
//	keydata  = HKDF(salt=ck, ikm=ZEROLEN, info="TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:32]
//	symmKey_ck = keydata[32:64]
//
// This is the recommended way to create a session after ECIES key exchange.
//
// # Limitation: the initial keys are not derived per the specification
//
// The spec obtains the ratchet inputs from the New Session Reply handshake:
// DH_INITIALIZE takes rootKey = "chainKey from Payload Section" and k = "from
// the New Session KDF or split()", and the two directions get separate tag sets
// ("The chainKey and k from Bob's NSR Payload Section are used as inputs for
// the initial ES DH Ratchets (both directions...)").
//
// This constructor has no handshake payload section to draw on, so it uses the
// caller's shared secret as the payload chain key. The KDFs it applies (Split,
// KDFDHRatchetStep, TagAndKeyGenKeys, STInitialization, SessionTagKeyGen,
// SymmetricRatchet) are exactly the spec's, and the directions are independent
// as section 4a requires, but the initial seed is not handshake-derived, so a
// session created here will not interoperate with a Java I2P router. Use it for
// local ratcheting and tests; for on-network sessions the keys must come from a
// spec-compliant New Session / New Session Reply handshake, which this package
// does not implement (see the ecies package docs for the scope boundary).
//
// Parameters:
//   - sharedSecret: The 32-byte ECIES-X25519 shared secret
//   - ourPrivKey: Our ephemeral private key (for DH ratchet)
//   - theirPubKey: Their public key (for DH ratchet)
//
// Returns:
//   - *Session: The initialized session ready for message encryption
//   - error: Any error during key derivation
//
// Example:
//
//	// After ECIES key exchange
//	session, err := ratchet.NewSessionFromECIES(sharedSecret, ourPriv, theirPub)
//	if err != nil {
//	    return err
//	}
//	defer session.Zero()
//
//	// Encrypt message: the session yields the per-message key, the session tag,
//	// and the spec's counter nonce; the caller does the ChaCha20-Poly1305
//	// encryption with them.
//	messageKey, tag, nonce, _ := session.EncryptMessage(plaintext)
func NewSessionFromECIES(sharedSecret, ourPrivKey, theirPubKey [32]byte) (*Session, error) {
	return NewSessionFromECIESWithRole(sharedSecret, ourPrivKey, theirPubKey, RoleInitiator)
}

// NewSessionFromECIESWithRole creates a session from an ECIES shared secret and
// assigns the local endpoint a handshake role, which determines which half of
// the Noise Split() output each direction uses.
//
// Spec section 4a makes the split mandatory: "After the final handshake KDF on
// bound sessions, Bob and Alice must run the Noise Split() function on the
// resulting CipherState to create independent symmetric and tag chain keys for
// inbound and outbound sessions." Both peers run the same split on the same
// chain key, so the role is what keeps the two directions from colliding: the
// initiator sends on k1 and receives on k2, the responder sends on k2 and
// receives on k1.
//
// When a single program creates both endpoints (tests, in-process tunnels),
// give them opposite roles; if both are created with [RoleInitiator] they are
// the same session and their outbound chains collide.
func NewSessionFromECIESWithRole(sharedSecret, ourPrivKey, theirPubKey [32]byte, role Role) (*Session, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "NewSessionFromECIESWithRole"}).Debug("Creating new session from ECIES shared secret")

	// The spec's DH INITIALIZATION KDF takes "rootKey = chainKey from Payload
	// Section" and "k from the New Session KDF or split()". This constructor has
	// no handshake payload section, so the caller's shared secret stands in for
	// the payload chain key (see the limitation note above).
	rootKey := sharedSecret

	// Noise Split (spec section 4a): two independent keys, one per direction.
	k1, k2, err := Split(rootKey)
	if err != nil {
		return nil, err
	}
	kOut, kIn := k1, k2
	if role == RoleResponder {
		kOut, kIn = k2, k1
	}

	// DH INITIALIZE each direction separately: "a ratchet is for a single
	// direction... To generate keys for both directions, you have to ratchet
	// twice". Each direction gets its own next root key and chain key.
	sending, sendingRootKey, err := newDirection(rootKey, kOut)
	if err != nil {
		return nil, err
	}
	receiving, receivingRootKey, err := newDirection(rootKey, kIn)
	if err != nil {
		return nil, err
	}

	// Initialize the DH ratchet with the sending direction's root key.
	dhRatchet := NewDHRatchet(sendingRootKey, ourPrivKey, theirPubKey)

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "NewSessionFromECIESWithRole"}).Debug("Session created successfully from ECIES shared secret")

	return &Session{
		dhRatchet:        dhRatchet,
		sending:          sending,
		receiving:        receiving,
		role:             role,
		sendingRootKey:   sendingRootKey,
		receivingRootKey: receivingRootKey,
		lookaheadSize:    DefaultLookaheadWindow,
	}, nil
}

// newDirection runs the spec's DH INITIALIZATION KDF for one direction and
// seeds a fresh tag set from the resulting chain key.
//
//	keydata     = HKDF(salt=rootKey, ikm=k, info="KDFDHRatchetStep", 64)
//	nextRootKey = keydata[0:32]
//	ck          = keydata[32:64]
//
// It returns the direction's ratchet state and its next root key, which is the
// root-key input for a subsequent DH ratchet in the same direction.
func newDirection(rootKey, k [ChainKeySize]byte) (direction, [ChainKeySize]byte, error) {
	nextRootKey, ck, err := DH_INITIALIZEFull(rootKey, k)
	if err != nil {
		return direction{}, nextRootKey, oops.Wrapf(ErrKeyDerivationFailed, "failed to run DH INITIALIZATION KDF: %w", err)
	}
	d, err := newTagSet(ck)
	if err != nil {
		return direction{}, nextRootKey, err
	}
	return d, nextRootKey, nil
}

// newTagSet applies the spec's TagAndKeyGenKeys KDF to a DH_INITIALIZE chain
// key and returns the direction's two ratchets, seeded for a fresh tag set.
//
//	keydata    = HKDF(salt=ck, ikm=ZEROLEN, info="TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:32]
//	symmKey_ck = keydata[32:64]
func newTagSet(ck [ChainKeySize]byte) (direction, error) {
	keydata, err := kdf.StandardHKDF(ck[:], nil, []byte("TagAndKeyGenKeys"), 64)
	if err != nil {
		return direction{}, oops.Wrapf(ErrKeyDerivationFailed, "failed to run TagAndKeyGenKeys KDF: %w", err)
	}
	var sessTagCK, symmKeyCK [ChainKeySize]byte
	copy(sessTagCK[:], keydata[0:32])
	copy(symmKeyCK[:], keydata[32:64])
	clear(keydata)

	return direction{
		symRatchet: NewSymmetricRatchet(symmKeyCK),
		tagRatchet: NewTagRatchet(sessTagCK),
	}, nil
}

// NewSessionFromHandshake creates a new session from a handshake result.
// This is a convenience wrapper around NewSessionFromECIES.
//
// Parameters:
//   - handshake: The result of an ECIES key exchange
//
// Returns:
//   - *Session: The initialized session
//   - error: Any error during session creation
//
// Example:
//
//	handshake := HandshakeResult{
//	    SharedSecret: eciesSharedSecret,
//	    OurPrivKey:   ourEphemeralPriv,
//	    TheirPubKey:  theirStaticPub,
//	}
//	session, err := ratchet.NewSessionFromHandshake(handshake)
func NewSessionFromHandshake(handshake HandshakeResult) (*Session, error) {
	return NewSessionFromECIES(
		handshake.SharedSecret,
		handshake.OurPrivKey,
		handshake.TheirPubKey,
	)
}

// EncryptMessage advances the ratchets and returns the message key, session
// tag, and AEAD nonce for the next outbound message. This method:
//  1. Generates a unique session tag for this message
//  2. Derives a message encryption key from the symmetric ratchet
//  3. Computes the spec's counter nonce from the message number
//  4. Advances both ratchets for forward secrecy
//
// It does NOT itself encrypt the plaintext: the caller must use the returned
// messageKey and nonce with a ChaCha20-Poly1305 AEAD to produce the ciphertext,
// and send that ciphertext together with the returned session tag so the
// recipient can identify which session (and message) it belongs to. Per spec
// section 1h the session tag is the AEAD associated data.
//
// Parameters:
//   - plaintext: The message to derive a key for (used only for logging; the
//     caller encrypts it with the returned key)
//
// Returns:
//   - messageKey: The 32-byte encryption key to use with ChaCha20-Poly1305
//   - tag: The 8-byte session tag (also the AEAD associated data)
//   - nonce: The 12-byte counter nonce for this message
//   - error: Any error during encryption
//
// Example:
//
//	messageKey, sessionTag, nonce, err := session.EncryptMessage(plaintext)
//	if err != nil {
//	    return err
//	}
//
//	// Use messageKey with ChaCha20-Poly1305 AEAD
//	aead, _ := chacha20poly1305.NewAEAD(messageKey)
//	ciphertext, authTag, _ := aead.Encrypt(plaintext, sessionTag[:], nonce[:])
func (s *Session) EncryptMessage(plaintext []byte) (messageKey [32]byte, tag [8]byte, nonce [NonceSize]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.EncryptMessage", "plaintext_len": len(plaintext), "message_num": s.sending.messageNum}).Debug("Encrypting message")

	// Spec §3: 65535 is the maximum valid message number, so a tag set carries
	// numbers 0..65535 (65536 messages); only beyond that is a DH ratchet step
	// required. Matches go-noise's MaxMessageNumber enforcement.
	if s.sending.messageNum > MaxMessagesPerTagset {
		return messageKey, tag, nonce, ErrTagsetExhausted
	}

	// The AEAD nonce is this message's number in the sending chain (spec
	// section 1h: "n = The message number N in the current chain"), captured
	// before the counter is advanced. Each direction has its own counter, so
	// the two directions never reuse a nonce.
	nonce = DataNonce(s.sending.messageNum)

	// Generate session tag for this message
	tag, err = s.sending.tagRatchet.GenerateNextTag()
	if err != nil {
		return messageKey, tag, nonce, oops.Wrapf(err, "failed to generate session tag")
	}

	// Derive message encryption key
	messageKey, err = s.sending.symRatchet.DeriveMessageKey(s.sending.messageNum)
	if err != nil {
		return messageKey, tag, nonce, oops.Wrapf(err, "failed to derive message key")
	}

	// Advance symmetric ratchet for forward secrecy
	if err := s.sending.symRatchet.Advance(); err != nil {
		return messageKey, tag, nonce, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}

	// Increment message number
	s.sending.messageNum++

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.EncryptMessage", "session_tag": tag}).Debug("Message encrypted successfully")

	return messageKey, tag, nonce, nil
}

// DecryptMessage looks up a received session tag in the receiver's look-ahead
// window and returns the message key and AEAD nonce associated with it.
//
// Tags are matched against the pre-computed window so that out-of-order delivery
// within the window still resolves to the correct key; the tag and symmetric key
// ratchets advance in lockstep as the contiguous head of the window is consumed.
//
// Parameters:
//   - tag: The 8-byte session tag received with the ciphertext
//
// Returns:
//   - messageKey: The 32-byte decryption key to use with ChaCha20-Poly1305
//   - nonce: The 12-byte counter nonce for this message's number
//   - error: Any error if the tag is invalid
//
// Example:
//
//	messageKey, nonce, err := session.DecryptMessage(sessionTag)
//	if err != nil {
//	    return err
//	}
//
//	// Use messageKey with ChaCha20-Poly1305 AEAD
//	aead, _ := chacha20poly1305.NewAEAD(messageKey)
//	plaintext, _ := aead.Decrypt(ciphertext, authTag, sessionTag[:], nonce[:])
func (s *Session) DecryptMessage(tag [8]byte) (messageKey [32]byte, nonce [NonceSize]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage", "session_tag": tag, "message_num": s.receiving.messageNum}).Debug("Decrypting message")

	// Only the inbound direction has a look-ahead window: the spec's receiver
	// "must ratchet ahead by the max window size and store the tags in a 'tag
	// set'" (section 4b). The outbound chain is advanced by EncryptMessage.
	if len(s.receiving.lookahead) == 0 {
		s.rebuildLookahead()
	}

	idx := -1
	for i := range s.receiving.lookahead {
		if s.receiving.lookahead[i].tag == tag && !s.receiving.lookahead[i].used {
			idx = i
			break
		}
	}
	if idx < 0 {
		log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage", "received_tag": tag}).Warn("Session tag not in lookahead window")
		return messageKey, nonce, oops.Errorf("invalid session tag: tag mismatch")
	}

	matched := s.receiving.lookahead[idx]
	s.receiving.lookahead[idx].used = true

	// Advance the real ratchets past the contiguous run of received messages at
	// the head of the window. Unreceived messages further along keep their
	// cached keys, so out-of-order delivery within the window still resolves to
	// the correct key (spec sections 4b and 4c: the receiver "should keep the
	// 'N' value associated with each session tag" and cache "the keys for any
	// previous tags that have not yet been received").
	for len(s.receiving.lookahead) > 0 && s.receiving.lookahead[0].used {
		if err := s.receiving.tagRatchet.Advance(); err != nil {
			return messageKey, nonce, oops.Wrapf(err, "failed to advance tag ratchet")
		}
		if err := s.receiving.symRatchet.Advance(); err != nil {
			return messageKey, nonce, oops.Wrapf(err, "failed to advance symmetric ratchet")
		}
		s.receiving.messageNum++
		s.receiving.lookahead = s.receiving.lookahead[1:]
	}
	s.fillLookahead()

	// The AEAD nonce is the matched message number (spec section 1h: "n = The
	// message number N in the current chain, as retrieved from the associated
	// Session Tag"). Returning it lets the caller decrypt an out-of-order
	// message, since the nonce is not otherwise recoverable from the tag.
	nonce = DataNonce(matched.num)

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.DecryptMessage"}).Debug("Message decrypted successfully")

	return matched.key, nonce, nil
}

// fillLookahead extends the receiving direction's look-ahead window back up to
// lookaheadSize entries by walking copies of its tag and symmetric ratchets.
// Existing (possibly already-received) entries are left untouched, so keys
// cached for out-of-order messages are not discarded.
func (s *Session) fillLookahead() {
	size := s.lookaheadSize
	if size <= 0 {
		size = DefaultLookaheadWindow
	}
	if size > MaxLookaheadWindow {
		size = MaxLookaheadWindow
	}
	if len(s.receiving.lookahead) >= size {
		return
	}

	// Walk copies so the real ratchet positions are not advanced.
	tagProbe := *s.receiving.tagRatchet
	symProbe := *s.receiving.symRatchet
	// Skip the entries already cached in the window.
	for i := 0; i < len(s.receiving.lookahead); i++ {
		if err := tagProbe.Advance(); err != nil {
			break
		}
		if err := symProbe.Advance(); err != nil {
			break
		}
	}

	for len(s.receiving.lookahead) < size {
		tag, err := tagProbe.PeekNextTag()
		if err != nil {
			break
		}
		key, err := symProbe.DeriveMessageKey(0)
		if err != nil {
			break
		}
		// The slot's message number is its absolute position in the chain: the
		// number the ratchet will reach once the existing entries are consumed.
		num := s.receiving.messageNum + uint32(len(s.receiving.lookahead))
		s.receiving.lookahead = append(s.receiving.lookahead, lookaheadEntry{tag: tag, key: key, num: num})
		if err := tagProbe.Advance(); err != nil {
			break
		}
		if err := symProbe.Advance(); err != nil {
			break
		}
	}
}

// rebuildLookahead discards and recomputes the receiving direction's whole
// look-ahead window from its current ratchet positions. Called when the
// ratchets are reinitialized (DH ratchet step) or the window is empty.
func (s *Session) rebuildLookahead() {
	s.receiving.lookahead = nil
	s.fillLookahead()
}

// PerformDHRatchet performs a Diffie-Hellman ratchet step in the sending
// direction to derive a new tag set. This should be called periodically to
// maintain forward secrecy.
//
// Per the spec (section 4, DH RATCHET KDF + DH INITIALIZATION KDF), the chain
// key output of DH_INITIALIZE is split via the TagAndKeyGenKeys KDF:
//
//	keydata = HKDF(salt=ck, ikm=ZEROLEN, info="TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:32]
//	symmKey_ck = keydata[32:64]
//
// The sending direction's symmetric and tag ratchets are reinitialized from the
// split, and the sending-direction root key is advanced. The receiving
// direction is untouched: section 4a says "a ratchet is for a single direction",
// so the inbound half of a NextKey exchange is the separate
// [Session.PerformReceivingDHRatchet] call.
//
// Returns:
//   - chainKey: The DH chain key (ck) output of DH_INITIALIZE
//   - nextRootKey: The new root key for the sending direction
//   - error: Any error during ratchet operation
//
// Example:
//
//	// Periodically refresh keys
//	ck, nextRootKey, err := session.PerformDHRatchet()
//	if err != nil {
//	    return err
//	}
func (s *Session) PerformDHRatchet() (chainKey, nextRootKey [32]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.PerformDHRatchet"}).Debug("Performing DH ratchet")

	// Select the sending-direction root key before the ratchet step.
	s.dhRatchet.SetRootKey(s.sendingRootKey)

	nextRootKey, ck, err := s.dhRatchet.PerformRatchet()
	if err != nil {
		return chainKey, nextRootKey, err
	}
	chainKey = ck

	// A DH ratchet is for a single direction (spec section 4a: "a ratchet is
	// for a single direction... To generate keys for both directions, you have
	// to ratchet twice"), so only the sending chain is replaced here. The
	// inbound chain and its look-ahead window are untouched.
	//
	// PerformRatchet already ran DH RATCHET KDF + DH_INITIALIZE, so the new
	// tag set is seeded directly from the returned chain key.
	sending, err := newTagSet(ck)
	if err != nil {
		return chainKey, nextRootKey, err
	}
	s.sending.Zero()
	s.sending = sending
	s.sendingRootKey = nextRootKey

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.PerformDHRatchet"}).Debug("DH ratchet completed successfully")

	return chainKey, nextRootKey, nil
}

// PerformReceivingDHRatchet performs the DH ratchet step for the inbound
// direction after the peer has sent a new key, completing the key exchange.
//
// The spec requires a ratchet in each direction whenever new keys are
// exchanged: "You ratchet every time you generate and send a new key. You
// ratchet every time you receive a new key." A NextKey exchange therefore
// involves two calls, one per direction: [Session.PerformDHRatchet] for the
// direction this endpoint sends on, and this method for the direction it
// receives on. The receiver should keep listening on the previous inbound tag
// set for a short time (about 3 minutes) while the new one takes effect.
//
// The caller must first install the peer's new key with
// [Session.UpdateRemotePublicKey] and, if this endpoint is the one that
// generated the key being acknowledged, generate its own with
// [Session.GenerateNewDHKeyPair].
//
// Returns:
//   - chainKey: The DH chain key (ck) output of DH_INITIALIZE for the inbound direction
//   - nextRootKey: The new root key for the receiving direction
//   - error: Any error during ratchet operation
func (s *Session) PerformReceivingDHRatchet() (chainKey, nextRootKey [32]byte, err error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.PerformReceivingDHRatchet"}).Debug("Performing receiving DH ratchet")

	// Select the receiving-direction root key before the ratchet step.
	s.dhRatchet.SetRootKey(s.receivingRootKey)

	nextRootKey, ck, err := s.dhRatchet.PerformRatchet()
	if err != nil {
		return chainKey, nextRootKey, err
	}
	chainKey = ck

	receiving, err := newTagSet(ck)
	if err != nil {
		return chainKey, nextRootKey, err
	}
	s.receiving.Zero()
	s.receiving = receiving
	s.receivingRootKey = nextRootKey

	// The inbound tag set was replaced, so rebuild the look-ahead window from
	// the new ratchet positions.
	s.rebuildLookahead()

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.PerformReceivingDHRatchet"}).Debug("Receiving DH ratchet completed successfully")

	return chainKey, nextRootKey, nil
}

// GenerateNewDHKeyPair generates a fresh ephemeral key pair for this endpoint's
// DH ratchet and returns the public key to send to the peer in a NextKey block.
func (s *Session) GenerateNewDHKeyPair() ([32]byte, error) {
	return s.dhRatchet.GenerateNewKeyPair()
}

// UpdateRemotePublicKey updates the remote party's public key for DH ratchet.
// This is used when the remote party rotates their ephemeral key.
//
// Parameters:
//   - newPubKey: The new remote public key
//
// Returns:
//   - error: Any error during key update
func (s *Session) UpdateRemotePublicKey(newPubKey [32]byte) error {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.UpdateRemotePublicKey"}).Debug("Updating remote public key")
	return s.dhRatchet.UpdateKeys(newPubKey[:])
}

// Role returns the handshake role this endpoint was created with, which
// determines which half of the Noise Split() output it sends on.
func (s *Session) Role() Role {
	return s.role
}

// GetNextTag returns the next session tag this endpoint would send, without
// advancing the sending ratchet. This is useful for tag validation and session
// lookup. To inspect the inbound direction, use [Session.GetReceivingNextTag].
//
// Returns:
//   - [8]byte: The next expected session tag
func (s *Session) GetNextTag() ([8]byte, error) {
	return s.sending.tagRatchet.PeekNextTag()
}

// GetReceivingNextTag returns the next session tag expected from the peer
// without advancing the receiving ratchet.
func (s *Session) GetReceivingNextTag() ([8]byte, error) {
	return s.receiving.tagRatchet.PeekNextTag()
}

// GetMessageNumber returns the current sending-direction message number.
func (s *Session) GetMessageNumber() uint32 {
	return s.sending.messageNum
}

// GetReceivingMessageNumber returns the current receiving-direction message
// number, i.e. the number of inbound messages consumed in the current tag set.
func (s *Session) GetReceivingMessageNumber() uint32 {
	return s.receiving.messageNum
}

// Zero securely clears all session state from memory.
// This should be called when the session is no longer needed.
func (s *Session) Zero() {
	if s.dhRatchet != nil {
		s.dhRatchet.Zero()
	}
	s.sending.Zero()
	s.receiving.Zero()
	s.sendingRootKey = [ChainKeySize]byte{}
	s.receivingRootKey = [ChainKeySize]byte{}

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Session.Zero"}).Debug("Session state cleared")
}

// Zero clears one direction's ratchet state, including the per-message keys
// cached in its look-ahead window.
func (d *direction) Zero() {
	if d.symRatchet != nil {
		d.symRatchet.Zero()
	}
	if d.tagRatchet != nil {
		d.tagRatchet.Zero()
	}
	d.messageNum = 0
	// The look-ahead window caches per-message keys, so it must be zeroed too.
	for i := range d.lookahead {
		d.lookahead[i] = lookaheadEntry{}
	}
	d.lookahead = nil
}
