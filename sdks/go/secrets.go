package wslvault

import (
	"context"
	"fmt"
)

// SecretsClient provides methods for the KV secrets engine.
//
// Access via [Client.Secrets].
type SecretsClient struct {
	c *Client
}

// Get reads a secret at path and returns its data and metadata.
//
//	secret, err := client.Secrets.Get(ctx, "prod/database/password")
//	if err != nil { ... }
//	fmt.Println(secret.Data["password"])
func (s *SecretsClient) Get(ctx context.Context, path string) (*SecretData, error) {
	var out SecretData
	if err := s.c.do(ctx, "GET", fmt.Sprintf("/v1/secret/data/%s", path), requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Put writes data to a secret at path. If the secret already exists a new
// version is created. The response contains the newly created version number.
func (s *SecretsClient) Put(ctx context.Context, path string, data map[string]interface{}) (*WriteResponse, error) {
	body := map[string]interface{}{"data": data}
	var out WriteResponse
	if err := s.c.do(ctx, "POST", fmt.Sprintf("/v1/secret/data/%s", path), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete soft-deletes specific versions of a secret. Pass an empty slice (or
// nil) to delete the current (latest) version. Soft-deleted versions can be
// recovered; use [Destroy] for permanent deletion.
func (s *SecretsClient) Delete(ctx context.Context, path string, versions []int) error {
	if versions == nil {
		versions = []int{}
	}
	body := SecretDeleteRequest{Versions: versions}
	return s.c.do(ctx, "POST", fmt.Sprintf("/v1/secret/delete/%s", path), requestOptions{body: body, expectBody: false}, nil)
}

// Destroy permanently removes specific versions of a secret. Unlike [Delete],
// destroyed versions cannot be recovered.
func (s *SecretsClient) Destroy(ctx context.Context, path string, versions []int) error {
	if versions == nil {
		versions = []int{}
	}
	body := SecretDeleteRequest{Versions: versions}
	return s.c.do(ctx, "POST", fmt.Sprintf("/v1/secret/destroy/%s", path), requestOptions{body: body, expectBody: false}, nil)
}

// List returns all secret paths stored under prefix.
func (s *SecretsClient) List(ctx context.Context, prefix string) (*ListResponse, error) {
	params := map[string]string{"prefix": prefix}
	var out ListResponse
	if err := s.c.do(ctx, "GET", "/v1/secret/list", requestOptions{params: params, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
