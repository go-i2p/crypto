package red25519

// Spec test vectors from https://i2p.net/en/docs/specs/red25519/ §Test vectors.
//
// This file is generated verbatim from the specification's "Test vectors"
// section, which is produced by the reference implementation, so accepting these
// signatures is direct evidence of interoperability with a Java router rather
// than a self-consistent round-trip through our own code.
//
// Legend (from the spec):
//
//	edsk:  Ed25519 private key (random)
//	edpk:  Ed25519 public key corresponding to edsk
//	sk:    CONVERT_ED25519_PRIVATE(edsk)
//	vk:    CONVERT_ED25519_PUBLIC(edpk)
//	msg:
//	sig:   SIGN(sk, msg)
//	alpha: GENERATE_RANDOM()
//	rsk:   RANDOMIZE_PRIVATE(sk, alpha)
//	rvk:   RANDOMIZE_PUBLIC(vk, alpha)
//	rsig:  SIGN(rsk, msg)

import (
	"encoding/hex"
	"strings"
	"testing"
)

func mustH(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.Join(strings.Fields(s), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

type redVector struct {
	name                  string
	edsk, edpk, sk, vk    string
	msg, sig              string
	alpha, rsk, rvk, rsig string
}

func redVectors() []redVector {
	return []redVector{
		{
			name: "vector 1",
			edsk: "0101010101010101010101010101010101010101010101010101010101010101",
			edpk: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
			sk:   "58e86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef36e",
			vk:   "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
			msg:  "0202020202020202020202020202020202020202020202020202020202020202",
			sig: "61f5527f4d3b46de4b2c234390370bf715ae9098907a0d191ba1b44b23a8ac1a6a40437a5294e9503faaf9bd2b7f2fe7" +
				"ba44dec487b3185aba7ff7d7a17cd40f",
			alpha: "ae9ba9cbbc047c442448fca7c9f4e288a202ed520bfad0c784b792b7773cee08",
			rsk:   "8bb85f3c7a494a08890d7d142109c1a3501d04565d80227e2079097800fbe107",
			rvk:   "6fe128737b8e76fa66698a748b0dc0a89168dd8a0601c2b1c0b26835d323e9b3",
			rsig: "533053074d3b44f08723aab988ede9880a001b7a684d4a98f2d1b88fabee07a5b5c9430c69a690321e0cb8365d7aeb66" +
				"88bcbad2c0780e0c69e8a1b4a45f3001",
		},
		{
			name: "vector 2",
			edsk: "0202020202020202020202020202020202020202020202020202020202020202",
			edpk: "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
			sk:   "a83c626bc9c38c8c201878ebb1d5b0b50ac40e8986c78793db1d4ef369fca14e",
			vk:   "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
			msg:  "0303030303030303030303030303030303030303030303030303030303030303",
			sig: "0829e58eb5399870f009bd1f0270264e556424bda7a93fbcec99f6d9d75db46d5c3cb546d9947ca7c1200876c8775a90" +
				"c357a2aef3d2f16388242ee1914b1a0a",
			alpha: "98b615d9027e996cc2796c019d9c8beb46aa7d2b6eea2e5d98eb29eb1584c203",
			rsk:   "9fcfaa734852ca40b3810ebef590e138516e8cb4f4b1b6f0730978de7f806402",
			rvk:   "527e121090158419609e4a0d8de6f7d3271b353a8cd0b8172fe41468ea1e9177",
			rsig: "9a6961f35ed264a946cd6214b2326a6e6caa426c2a61bc14367fd278e0b5fb513ac065a69210a457f17d12ba8a496cfd" +
				"835002691affa8efcdecae48135c090f",
		},
		{
			name: "vector 3",
			edsk: "0303030303030303030303030303030303030303030303030303030303030303",
			edpk: "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
			sk:   "98aebbb178a551876bfaf8e1e530dac6aaf6c2ea1c8f8406a3ab37dfb40fbc65",
			vk:   "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
			msg:  "0404040404040404040404040404040404040404040404040404040404040404",
			sig: "ef5fd1488048fb0247e5883bd90f7b2ce1ffe9b143a5bf6156b76ac2c39d8fdbd0730d7111d9cec69a808f3d18268a91" +
				"f035b41b82c1fe06f394a615f93a8709",
			alpha: "ba17f5110fcea8a12e0bd3677e4088b874332c4e3e6c9911d9ec3fe0233d3e0a",
			rsk:   "c4ceed95e9208c189458fe772c9628021f2aef385bfb1d187c9877bfd84cfa0f",
			rvk:   "6e2b9b129bbe00fa964c996d40307dd01aff120e94fd15f17119341ecda3d7a0",
			rsig: "900ecc6306f895a8ccde97d3624799fd939062a87b69e09351903ba83ceeab2bef6e3c15e5d8400ed9151f7dce14bf4c" +
				"fc7ce3f4399e22455fc18a68ed931c03",
		},
		{
			name: "vector 4",
			edsk: "0404040404040404040404040404040404040404040404040404040404040404",
			edpk: "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
			sk:   "483e3c145d7e680a16676925fc045183d2f510cb2f660a1fc517c73762185d43",
			vk:   "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
			msg:  "0505050505050505050505050505050505050505050505050505050505050505",
			sig: "d76b8133e08e4ff58de6b7f2df95c84a8bb968addd1d1ff585d79a90f5cfe11f9aa21d0277908aecae3853ee44493f95" +
				"f2445df2da712f28eea435044e6fed03",
			alpha: "9a14f2755512a72a3a5a514379f3458c3f912fc5eba8711b0cf2bfda49c79104",
			rsk:   "2e0357164904c6d4f64ddcdcfa101bbc118740901b0f7c3ad1098712acdfee07",
			rvk:   "de0a291ee45634de9a051c9373b9378ffbe45a8532067a9a93a86b837c762908",
			rsig: "010dcc6a44e942a6f7d52704d957ad66a5c6452ad9b9442cc8ef724e41d6c3cea24eace9b22e0f9d2b9ade14c61bded3" +
				"3286e7e6340faaa0167a9f1f90001503",
		},
		{
			name: "vector 5",
			edsk: "0505050505050505050505050505050505050505050505050505050505050505",
			edpk: "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
			sk:   "48370d6146de919cc1ce472897775d9a6c2834c509e08e14efcb2b52188f946e",
			vk:   "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
			msg:  "0606060606060606060606060606060606060606060606060606060606060606",
			sig: "2c56c96801f99ae1f5e8d8edc87725e08aaf7fc77071f222f7c46084b41c5b41de1ee3df97217865633f7cceb11cedc3" +
				"a637ce047d2111cb6f372882e2d6b20b",
			alpha: "687944d00a53ca02a0787da2acb8f99994ea7453c8d140d93efbc2b70d852a07",
			rsk:   "35e598a6987bdb3685fdff552d5b3ea20013a918d2b1cfed2dc7ee092614bf05",
			rvk:   "9951414e4f29408031f212edc6c9cfe36550b4ce2aa968db49de6c93ca9d565b",
			rsig: "4b8f3e3baa8b4fdb99b0053036d569352e49c98c61800288f676aed77b9929b3f3278565d824c5566666d2c9ff789207" +
				"098d5f9d09dd89aa4945ca3866831e02",
		},
		{
			name: "vector 6",
			edsk: "0606060606060606060606060606060606060606060606060606060606060606",
			edpk: "8a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f17",
			sk:   "a83f248f80ff04de20a82fe12bd3551887168e372d239932ce812d0992d34078",
			vk:   "8a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f17",
			msg:  "0707070707070707070707070707070707070707070707070707070707070707",
			sig: "f4a00093daa26b48465e07ee5697ba44191fb5673b6ab71a31d2349a18aecbd6c4801be60ebf18cd7ce8ec5fe0988fc4" +
				"762908095063b55068ce4c7578c91504",
			alpha: "0158cda553d7e9769829a5d36d2b7ce05e9171d8d058a8630d31029001ffd409",
			rsk:   "41f8424d01be5b9406eb179da42fda51e5a7ff0ffe7b4196dbb22f9993d21502",
			rvk:   "cef5dc9b4a246025df56fb118e34c3f06d6213c4c6ab8a1d4297eb7845cb2824",
			rsig: "de23eec573f35ebf7ea9539b511ca5129213821525190fdf1c186c2788c1abb35bd40937defbc4112225d399a79a171c" +
				"f02c3eebbd6340bbdca7383906af1902",
		},
		{
			name: "vector 7",
			edsk: "0707070707070707070707070707070707070707070707070707070707070707",
			edpk: "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
			sk:   "28ad39fefd7fa3e200a9c626eef599e61a2d055c48a8288a4e7e4c4bca392878",
			vk:   "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
			msg:  "0808080808080808080808080808080808080808080808080808080808080808",
			sig: "e78bf2d340d9ae0af5dd81e4d58801b3872189a71573a12be343ed39cebab56a6bc1f01872bbb1d16b2be4a943a9ba90" +
				"fb7a4c97c3e5f20416890ceedf6e7e0c",
			alpha: "8e16161802e3c87857ae725dfa28d6222b326907f652e6c89f806882c0fb1a00",
			rsk:   "3bf8968b47adebf27b0d740fd2495777455f6e633efb0e53eefeb4cd8a354308",
			rvk:   "755a8f05633c45d0fac471a386776f63a7d28bc8d80e326ddde5484b20565e89",
			rsig: "6efdca4ba705bc05d4564f0ca626646679ac1cb2c3093618e95238ebd1c7aa09632ccefc324594447a01074bb473c3ce" +
				"94ccaae86e18f8f43477326a12ae6207",
		},
		{
			name: "vector 8",
			edsk: "0808080808080808080808080808080808080808080808080808080808080808",
			edpk: "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
			sk:   "3826c9c31226edde9501fd2589203cb3e6fe737876a845512b53ada2fa2ace74",
			vk:   "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
			msg:  "0909090909090909090909090909090909090909090909090909090909090909",
			sig: "1ed88a926dd80999d3a40efd3b74fa731729e28bb84e0430663822a69f9f4bccfd2bd0aa7325d9887eac76ddf08da65c" +
				"42eedaaec244c3241307570910778f05",
			alpha: "c4cc56d9c3e787ca60a54dfca65b4556f2dccabcac97e7a975e4efa1acb8920e",
			rsk:   "945371b503f5e1e843c08d0a3bad8962d8db3e3523402dfba0379d44a7e36003",
			rvk:   "db1730a0730ca0746a73f1880660ea5ea42f9d931760f3cdedc9cbe1c1d1b8d9",
			rsig: "db60c64b61e888696ca0a7ef7adb92b784e0e6070d0435818e99788022db8e8381ddcc1e27f044b8c3c75044e715d870" +
				"f3273a7f9cf85f1a59f4a7c95fded408",
		},
		{
			name: "vector 9",
			edsk: "0909090909090909090909090909090909090909090909090909090909090909",
			edpk: "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
			sk:   "388fe3ab30c0aabf54acd276f3d8bbbc2b7ca4a9495d204f255bacf578c74c46",
			vk:   "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
			msg:  "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
			sig: "dd5a8c6ed9331c074ea11f65b9290900931bdf01a47f01adc75583d2a3dcfc10b65c77a3e992678865e7dc713295749b" +
				"4dddd33fa167b96c6d6904818e4d6806",
			alpha: "b851f206eba78325ed5231cad059e8bd8a1e3d7f1e391058b3d9ab08d096cb03",
			rsk:   "3c91fe3eb2dbe484e88b25b5494b2827b69ae128689630a7d83458fe485e180a",
			rvk:   "601ab762eea5cd89ff34e0f661d1ca3932ba166ca67154b2e62afb85282dda81",
			rsig: "5a453378fdbb22b8f037ad61d144ce006201fea0c2c1472d463617c432786dfc47430d27649817a7fc26296c94bf922f" +
				"3863867c648ddd6709710bfa199aee02",
		},
		{
			name: "vector 10",
			edsk: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
			edpk: "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c",
			sk:   "0099bf92c41b5d3d309c3b074756e9707e40a9bcea229857f7cf551e8bb0fd45",
			vk:   "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c",
			msg:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			sig: "c54d64d550f7690ffdd108efc49f1c25a54282825e10328630710924b354cb4c138a523b1ada66a8fdc8b7efcae939fd" +
				"54b05552c30ca280d23199c391c5b707",
			alpha: "5eebb60818299d581fa68f5fcae4c2bb398a7e10876e27994d93d555075e7d05",
			rsk:   "aa349f2773b8b035f6ceecda965330d9b7ca27cd7191bff044632b74920e7b0b",
			rvk:   "d0c5fe8f83fd42202265efff804a1527c0eb0e1cce9781cf14571cd506eeed36",
			rsig: "28e96b6d4251b356e635e382ed89a37e7650d3035f98909e09a6cbe82c13e418fddb2106b7b527e198039da7221dae1a" +
				"0227f0a4ab88f06567e8fd9238acc106",
		},
	}
}

// TestRed25519SpecVectors checks the deterministic parts of the scheme against
// the reference vectors: the Ed25519 conversions, DERIVE_PUBLIC, both
// re-randomization functions, and VERIFY of the reference signatures.
//
// The signatures themselves cannot be byte-compared, because SIGN draws 80 random
// bytes for T; VERIFY is deterministic, so verifying the published sig is the
// interoperability test.
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

			// DERIVE_PUBLIC(sk) == vk, validating scalar multiplication and the
			// point encoding against the reference.
			derived, err := sk.Public()
			if err != nil {
				t.Fatalf("Public: %v", err)
			}
			if hex.EncodeToString(derived.Bytes()) != hex.EncodeToString(vkWant) {
				t.Errorf("DERIVE_PUBLIC(sk) = %x, want %x", derived.Bytes(), vkWant)
			}

			// VERIFY(vk, msg, sig): exercises HStar (personalization + length
			// prefix), point/scalar decoding, and the cofactor equation against a
			// signature this code never produced.
			ver, err := vk.NewVerifier()
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			if err := ver.Verify(msg, sig); err != nil {
				t.Errorf("VERIFY of reference signature failed: %v", err)
			}

			// A reference signature must not verify against a different message.
			if err := ver.Verify(append([]byte{}, msg[:len(msg)-1]...), sig); err == nil {
				t.Error("reference signature verified against a truncated message")
			}

			// RANDOMIZE_PRIVATE(sk, alpha) == rsk
			var bf BlindingFactor
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

			// VERIFY(rvk, msg, rsig)
			rvkVer, err := rvk.NewVerifier()
			if err != nil {
				t.Fatalf("rvk.NewVerifier: %v", err)
			}
			if err := rvkVer.Verify(msg, rsig); err != nil {
				t.Errorf("VERIFY of reference blinded signature failed: %v", err)
			}

			// The invariant §Design requires:
			// RANDOMIZE_PUBLIC(vk, alpha) == DERIVE_PUBLIC(RANDOMIZE_PRIVATE(sk, alpha))
			rskPub, err := rsk.Public()
			if err != nil {
				t.Fatalf("rsk.Public: %v", err)
			}
			if hex.EncodeToString(rskPub.Bytes()) != hex.EncodeToString(rvk) {
				t.Errorf("blinding invariant broken: DERIVE_PUBLIC(rsk) = %x, rvk = %x", rskPub.Bytes(), rvk)
			}

			// And our own signer under the blinded key must produce signatures the
			// reference verifier's key accepts.
			signer, err := rsk.NewSigner()
			if err != nil {
				t.Fatalf("rsk.NewSigner: %v", err)
			}
			ours, err := signer.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if err := rvkVer.Verify(msg, ours); err != nil {
				t.Errorf("our signature under the reference blinded key did not verify: %v", err)
			}
		})
	}
}

// sameScalar compares two private-key encodings up to their mod-L representative,
// since sk from CONVERT_ED25519_PRIVATE is stored clamped (>= L) while
// RANDOMIZE_PRIVATE returns a reduced value.
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
