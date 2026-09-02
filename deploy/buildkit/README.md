# Remote BuildKit for CI

CI builds the amd64 service images on a `buildkitd` daemon running on
**debian001**, reached over **TCP + mTLS** from the self-hosted runner. This
replaces the buildx *kubernetes* driver, which streamed through the k3s API
server's kubelet proxy (`:10250`) — a path that flaps in this cluster and used
to fail the entire build matrix at once. The *remote* driver puts no API server
or kubelet in the build path.

- Daemon: `buildkitd.yaml` (Deployment, pinned to debian001, hostPort `1234`).
- Runner → daemon: `tcp://192.168.1.140:1234` (`BUILDKIT_REMOTE` in `ci.yml`).
- Client certs on the runner: `$BUILDKIT_CERTS` (`/Users/balinderwalia/.wslvault-buildkit`).

## One-time setup

TLS material is **not** in git. Generate a CA and a server + client keypair
(server SAN must include the node IP):

```bash
NODE_IP=192.168.1.140
openssl genrsa -out ca-key.pem 4096
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 \
  -subj "/CN=wslvault-buildkit-ca" -out ca.pem

openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -subj "/CN=buildkitd" -out server.csr
printf "subjectAltName=IP:%s,IP:127.0.0.1,DNS:buildkitd\nextendedKeyUsage=serverAuth\n" "$NODE_IP" > server-ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 3650 -sha256 -extfile server-ext.cnf -out server-cert.pem

openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -subj "/CN=buildkit-client" -out client.csr
printf "extendedKeyUsage=clientAuth\n" > client-ext.cnf
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 3650 -sha256 -extfile client-ext.cnf -out client-cert.pem
```

Install the server certs as the Secret the Deployment mounts, and deploy:

```bash
kubectl create secret generic buildkitd-tls -n default \
  --from-file=ca.pem=ca.pem \
  --from-file=cert.pem=server-cert.pem \
  --from-file=key.pem=server-key.pem
kubectl apply -f deploy/buildkit/buildkitd.yaml
```

Install the client certs on the runner host (names must match `ci.yml`):

```bash
mkdir -p /Users/balinderwalia/.wslvault-buildkit
cp ca.pem client-cert.pem client-key.pem /Users/balinderwalia/.wslvault-buildkit/
chmod 600 /Users/balinderwalia/.wslvault-buildkit/*.pem
```

## Verify

```bash
docker buildx create --name k3s-remote --driver remote \
  --driver-opt "cacert=$HOME/.wslvault-buildkit/ca.pem,cert=$HOME/.wslvault-buildkit/client-cert.pem,key=$HOME/.wslvault-buildkit/client-key.pem" \
  tcp://192.168.1.140:1234
docker buildx inspect k3s-remote --bootstrap   # Status: running, linux/amd64
```

## Notes

- The daemon is privileged; mTLS is what keeps it from being an open
  root-equivalent build service on the LAN. Keep the client key secret.
- If debian001 changes, update the server cert SAN, `nodeSelector`, and
  `BUILDKIT_REMOTE`.
- Local build cache (`/tmp/.buildx-cache-*`) stays on the runner and still works
  with the remote driver.
