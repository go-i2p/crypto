package red25519

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Spec test vectors from https://i2p.net/en/docs/specs/red25519/ §Test vectors.
// These are produced by the reference (Java) implementation, so accepting them is
// direct evidence of interoperability, not a self-consistent round-trip.
type redVector struct {
	name  string
	edsk  string // Ed25519 private key (seed)
	edpk  string // Ed25519 public key
	sk    string // CONVERT_ED25519_PRIVATE(edsk)
	vk    string // CONVERT_ED25519_PUBLIC(edpk)
	msg   string
	sig   string // SIGN(sk, msg)
	alpha string // GENERATE_RANDOM()
	rsk   string // RANDOMIZE_PRIVATE(sk, alpha)
	rvk   string // RANDOMIZE_PUBLIC(vk, alpha)
	rsig  string // SIGN(rsk, msg)
}

func mustH(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.Join(strings.Fields(s), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func redVectors() []redVector {
	return []redVector{
		{
			name:  "vector 1",
			edsk:  "0101010101010101010101010101010101010101010101010101010101010101",
			edpk:  "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
			sk:    "58e86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef36e",
			vk:    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
			msg:   "0202020202020202020202020202020202020202020202020202020202020202",
			sig:   "61f5527f4d3b46de4b2c234390370bf715ae9098907a0d191ba1b44b23a8ac1a6a40437a5294e9503faaf9bd2b7f2fe7ba44dec487b3185aba7ff7d7a17cd40f",
			alpha: "ae9ba9cbbc047c442448fca7c9f4e288a202ed520bfad0c784b792b7773cee08",
			rsk:   "8bb85f3c7a494a08890d7d142109c1a3501d04565d80227e2079097800fbe107",
			rvk:   "6fe128737b8e76fa66698a748b0dc0a89168dd8a0601c2b1c0b26835d323e9b3",
			rsig:  "533053074d3b44f08723aab988ede9880a001b7a684d4a98f2d1b88fabee07a5b5c9430c69a690321e0cb8365d7aeb6688bcbad2c0780e0c69e8a1b4a45f3001",
		},
		{
			name:  "vector 2",
			edsk:  "0202020202020202020202020202020202020202020202020202020202020202",
			edpk:  "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
			sk:    "a83c626bc9c38c8c201878ebb1d5b0b50ac40e8986c78793db1d4ef369fca14e",
			vk:    "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
			msg:   "0303030303030303030303030303030303030303030303030303030303030303",
			sig:   "0829e58eb5399870f009bd1f0270264e556424bda7a93fbcec99f6d9d75db46d5c3cb546d9947ca7c1200876c8775a90c357a2aef3d2f16388242ee1914b1a0a",
			alpha: "98b615d9027e996cc2796c019d9c8beb46aa7d2b6eea2e5d98eb29eb1584c203",
			rsk:   "9fcfaa734852ca40b3810ebef590e138516e8cb4f4b1b6f0730978de7f806402",
			rvk:   "527e121090158419609e4a0d8de6f7d3271b353a8cd0b8172fe41468ea1e9177",
			rsig:  "9a6961f35ed264a946cd6214b2326a6e6caa426c2a61bc14367fd278e0b5fb513ac065a69210a457f17d12ba8a496cfd835002691affa8efcdecae48135c090f",
		},
		{
			name:  "vector 3",
			edsk:  "0303030303030303030303030303030303030303030303030303030303030303",
			edpk:  "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
			sk:    "98aebbb178a551876bfaf8e1e530dac6aaf6c2ea1c8f8406a3ab37dfb40fbc65",
			vk:    "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
			msg:   "0404040404040404040404040404040404040404040404040404040404040404",
			sig:   "ef5fd1488048fb0247e5883bd90f7b2ce1ffe9b143a5bf6156b76ac2c39d8dbdd0730d7111d9cec69a808f3d18268a91f035b41b82c1fe06f394a615f93a8709",
			alpha: "ba17f5110fcea8a12e0bd3677e4088b874332c4e3e6c9911d9ec3fe0233d3e0a",
			rsk:   "c4ceed95e9208c189458fe772c9628021f2aef385bfb1d187c9877bfd84cfa0f",
			rvk:   "6e2b9b129bbe00fa964c996d40307dd01aff120e94fd15f17119341ecda3d7a0",
			rsig:  "900ecc6306f895a8ccde97d3624799fd939062a87b69e09351903ba83ceeab2bef6e3c15e5d8400ed9151f7dce14bf4cfc7ce3f4399e22455fc18a68ed931c03",
		},
		{
			name:  "vector 5",
			edsk:  "0505050505050505050505050505050505050505050505050505050505050505",
			edpk:  "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
			sk:    "48370d6146de919cc1ce472897775d9a6c2834c509e08e14efcb2b52188f946e",
			vk:    "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
			msg:   "0606060606060606060606060606060606060606060606060606060606060606",
			sig:   "2c56c96801f99ae1f5e8d8edc87725e08aaf7fc77071f222f7c46084b41c5b41de1ee3df97217865633f7cceb11cedc3a637ce047d2111cb6f372882e2d6b20b",
			alpha: "687944d00a53ca02a0787da2acb8f99994ea7453c8d140d93efbc2b70d852a07",
			rsk:   "35e598a6987bdb3685fdff552d5b3ea20013a918d2b1cfed2dc7ee092614bf05",
			rvk:   "9951414e4f29408031f212edc6c9cfe36550b4ce2aa968db49de6c93ca9d565b",
			rsig:  "4b8f3e3baa8b4fdb99b0053036d569352e49c98c61800288f676aed77b9929b3f3278565d824c5566666d2c9ff789207098d5f9d09dd89aa4945ca3866831e02",
		},
		{
			name:  "vector 10",
			edsk:  "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
			edpk:  "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c",
			sk:    "0099bf92c41b5d3d309c3b074756e9707e40a9bcea229857f7cf551e8bb0fd45",
			vk:    "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c",
			msg:   "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			sig:   "c54d64d550f7690ffdd108efc49f1c25a54282825e10328630710924b354cb4c138a523b1ada66a8fdc8b7efcae939fd54b05552c30ca280d23199c391c5b707",
			alpha: "5eebb60818299d581fa68f5fcae4c2bb398a7e10876e27994d93d555075e7d05",
			rsk:   "aa349f2773b8b035f6ceecda965330d9b7ca27cd7191bff044632b74920e7b0b",
			rvk:   "d0c5fe8f83fd42202265efff804a1527c0eb0e1cce9781cf14571cd506eeed36",
			rsig:  "28e96b6d4251b356e635e382ed89a37e7650d3035f98909e09a6cbe82c13e418fddb2106b7b527e198039da7221dae1a0227f0a4ab88f06567e8fd9238acc106",
		},
	}
}

// TestRed25519SpecVectors checks the deterministic parts of the scheme against
// the reference vectors: the Ed25519 conversion, DERIVE_PUBLIC, the two
// re-randomization functions, and VERIFY of the reference signatures.
func TestRed25519SpecVectors(t *testing.T) {
	for _, v := range redVectors() {
		t.Run(v.name, func(t *testing.T) {
			edsk := mustH(t, v.edsk)
			edpk := mustH(t, v.edpk)
			skWant := mustH(t, v.sk)
			vkWant := mustH(t, v.vk)
			msg := mustH(t, v.msg)
			sig := mustH(t, v.sig)
			alpha := mustH(t, v.alpha)
			rskWant := mustH(t, v.rsk)
			rvkWant := mustH(t, v.rvk)
			rsig := mustH(t, v.rsig)

			// CONVERT_ED25519_PRIVATE(edsk) == sk
			sk, err := ConvertEd25519PrivateKey(edsk)
			if err != nil {
				t.Fatalf("ConvertEd25519PrivateKey: %v", err)
			}
			if hex.EncodeToString(sk) != hex.EncodeToString(skWant) {
				t.Errorf("CONVERT_ED25519_PRIVATE = %x, want %x", sk, skWant)
			}

			// CONVERT_ED25519_PUBLIC(edpk) == vk
			vk, err := ConvertEd25519PublicKey(edpk)
			if err != nil {
				t.Fatalf("ConvertEd25519PublicKey: %v", err)
			}
			if hex.EncodeToString(vk) != hex.EncodeToString(vkWant) {
				t.Errorf("CONVERT_ED25519_PUBLIC = %x, want %x", vk, vkWant)
			}

			// DERIVE_PUBLIC(sk) == vk  (validates scalar mult + point encoding)
			derived, err := sk.Public()
			if err != nil {
				t.Fatalf("Public: %v", err)
			}
			if hex.EncodeToString(derived.Bytes()) != hex.EncodeToString(vkWant) {
				t.Errorf("DERIVE_PUBLIC(sk) = %x, want %x", derived.Bytes(), vkWant)
			}

			// VERIFY(vk, msg, sig) == true  (validates HStar + cofactor verify +
			// scalar/point decoding against the reference signature)
			ver, err := vk.NewVerifier()
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			if err := ver.Verify(msg, sig); err != nil {
				t.Errorf("VERIFY of reference signature failed: %v", err)
			}

			// RANDOMIZE_PRIVATE(sk, alpha) == rsk
			bf := ([ScalarSize]byte{})
			copy(bf[:], alpha)
			rsk, err := BlindPrivateKey(sk, bf)
			if err != nil {
				t.Fatalf("BlindPrivateKey: %v", err)
			}
			if !sameScalar(t, rsk, rskWant) {
				t.Errorf("RANDOMIZE_PRIVATE = %x, want %x (mod L)", rsk, rskWant)
			}

			// RANDOMIZE_PUBLIC(vk, alpha) == rvk
			rvk, err := BlindPublicKey(vk, bf)
			if err != nil {
				t.Fatalf("BlindPublicKey: %v", err)
			}
			if hex.EncodeToString(rvk) != hex.EncodeToString(rvkWant) {
				t.Errorf("RANDOMIZE_PUBLIC = %x, want %x", rvk, rvkWant)
			}

			// VERIFY(rvk, msg, rsig) == true
			rvkVer, err := rvk.NewVerifier()
			if err != nil {
				t.Fatalf("rvk.NewVerifier: %v", err)
			}
			if err := rvkVer.Verify(msg, rsig); err != nil {
				t.Errorf("VERIFY of reference blinded signature failed: %v", err)
			}

			// The invariant the spec requires:
			// RANDOMIZE_PUBLIC(vk, alpha) == DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk, alpha))
			rskPub, err := rsk.Public()
			if err != nil {
				t.Fatalf("rsk.Public: %v", err)
			}
			if hex.EncodeToString(rskPub.Bytes()) != hex.EncodeToString(rvk) {
				t.Errorf("blinding invariant broken: DERIVE_PUBLIC(rsk) = %x, rvk = %x", rskPub.Bytes(), rvk)
			}
		})
	}
}

// sameScalar compares two private-key encodings up to the mod-L representative,
// since sk is stored clamped (>= L) while RANDOMIZE_PRIVATE returns a reduced
// value.
func sameScalar(t *testing.T, got, want []byte) bool {
	t.Helper()
	if hex.EncodeToString(got) == hex.EncodeToString(want) {
		return true
	}
	a, err := reduceScalarModL(got)
	if err != nil {
		t.Fatalf("reduce got: %v", err)
	}
	b, err := reduceScalarModL(want)
	if err != nil {
		t.Fatalf("reduce want: %v", err)
	}
	return a.Equal(b) == 1
}
