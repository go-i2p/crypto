package types

type PublicKey interface {
	Len() int
	Bytes() []byte
}

type ReceivingPublicKey interface {
	Len() int
	Bytes() []byte
	NewEncrypter() (Encrypter, error)
}
