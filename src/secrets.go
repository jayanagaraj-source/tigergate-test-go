package src

// Secret-scanner fixtures. Every value here is SYNTHETIC. They are shaped
// to match common secret detectors but are not live credentials.

import "os"

const APIKey = "test-fixture-not-a-real-secret"

const (
	// AWS documentation example keys (public, never valid)
	AWSAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// GitHub classic PAT shape: ghp_ + 36 chars
	GitHubToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"

	// Slack bot token. The real Slack bot-token shape (the vendor prefix plus
	// two digit groups and an alphanumeric tail) is NOT reproduced here, not
	// even in this comment: GitHub push protection blocks any push containing
	// that literal, so the fixture could never be committed. Keyword detection
	// (the identifier name) still applies; vendor-pattern detection does not.
	// See SECURITY_FIXTURES.md.
	SlackBotToken = "FIXTURE-slack-bot-token-shape-omitted-for-push-protection"

	// Stripe secret key. Stripe's own published test key was here, but GitHub
	// push protection blocks that literal, so the vendor test-key shape is
	// omitted for the same reason as Slack above — including in this comment.
	StripeSecretKey = "FIXTURE-stripe-secret-key-shape-omitted-for-push-protection"

	// Google API key shape: AIza + 35 chars
	GoogleAPIKey = "AIzaSyA-FAKE-FIXTURE-KEY-00000000000000"

	// SendGrid shape: SG.<22>.<43>
	SendGridAPIKey = "SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// Twilio-style SID/token
	TwilioAccountSID = "AC00000000000000000000000000000000"
	TwilioAuthToken  = "00000000000000000000000000000000"

	// Generic secrets
	JWTSigningSecret = "change-me-jwt-secret-2024"
	AdminPassword    = "admin123!"
	EncryptionKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	// Connection strings with embedded credentials
	DatabaseURL = "postgres://app:Sup3rS3cret!@db.internal:5432/prod?sslmode=disable"
	RedisURL    = "redis://:redispass123@cache.internal:6379/0"
	MongoURL    = "mongodb://root:rootpass@mongo.internal:27017/admin"
	SMTPURL     = "smtp://mailer:MailPass!23@smtp.internal:587"
)

// Fake private key. The base64 body is NOT a valid key; scanners key on the
// PEM header.
const PrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAFAKEFIXTUREKEYFAKEFIXTUREKEYFAKEFIXTUREKEYFAKEFIXTU
REKEYFAKEFIXTUREKEYFAKEFIXTUREKEYFAKEFIXTUREKEYFAKEFIXTUREKEYFAKEFI
XTUREKEYFAKEFIXTUREKEYFAKEFIXTUREKEYFAKEFIXTUREKEYFAKEFIXTUREKEY==
-----END RSA PRIVATE KEY-----`

// SAFE: secret read from environment. Must NOT be flagged as hard-coded.
func SecretFromEnv() string {
	return os.Getenv("APP_SECRET")
}
