package wslvault

import (
	"context"
	"fmt"
)

// TransitClient provides methods for the transit encryption engine.
//
// Access via [Client.Transit].
type TransitClient struct {
	c *Client
}

// Encrypt encrypts base64-encoded plaintext using the named transit key and
// returns a versioned ciphertext.
func (t *TransitClient) Encrypt(ctx context.Context, keyName, plaintext string) (*TransitEncryptResponse, error) {
	body := map[string]string{"plaintext": plaintext}
	var out TransitEncryptResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/encrypt/%s", keyName), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Decrypt decrypts a versioned ciphertext using the named transit key.
// The returned Plaintext is base64-encoded.
func (t *TransitClient) Decrypt(ctx context.Context, keyName, ciphertext string) (*TransitDecryptResponse, error) {
	body := map[string]string{"ciphertext": ciphertext}
	var out TransitDecryptResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/decrypt/%s", keyName), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Sign signs base64-encoded data using the named transit key and returns a
// detached signature.
func (t *TransitClient) Sign(ctx context.Context, keyName, data string) (*TransitSignResponse, error) {
	body := map[string]string{"data": data}
	var out TransitSignResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/sign/%s", keyName), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify checks a signature over base64-encoded data using the named transit
// key. Returns a response whose Valid field indicates whether the signature is
// authentic.
func (t *TransitClient) Verify(ctx context.Context, keyName, data, signature string) (*TransitVerifyResponse, error) {
	body := map[string]string{"data": data, "signature": signature}
	var out TransitVerifyResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/verify/%s", keyName), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Hash computes a SHA-256 hash of inputData using the named key context and
// returns the hex-encoded digest.
func (t *TransitClient) Hash(ctx context.Context, keyName, inputData string) (*TransitHashResponse, error) {
	body := map[string]string{"input": inputData}
	var out TransitHashResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/hash/%s", keyName), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HMAC computes an HMAC over inputData using the named transit key.
func (t *TransitClient) HMAC(ctx context.Context, keyName, inputData string) (*TransitHmacResponse, error) {
	body := map[string]string{"input": inputData}
	var out TransitHmacResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/hmac/%s", keyName), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateKey creates a new named transit key with the server's default
// algorithm (typically AES-256-GCM96).
func (t *TransitClient) CreateKey(ctx context.Context, keyName string) (*TransitKeyResponse, error) {
	var out TransitKeyResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/keys/%s", keyName), requestOptions{body: map[string]interface{}{}, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateKey rotates the named transit key, adding a new key version. Existing
// ciphertexts encrypted with older versions can still be decrypted.
func (t *TransitClient) RotateKey(ctx context.Context, keyName string) (*TransitKeyRotateResponse, error) {
	var out TransitKeyRotateResponse
	if err := t.c.do(ctx, "POST", fmt.Sprintf("/v1/transit/keys/%s/rotate", keyName), requestOptions{body: map[string]interface{}{}, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
