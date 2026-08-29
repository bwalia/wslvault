{{/*
_helpers.tpl - Shared template helpers for the wslvault Helm chart.

Naming conventions follow the Helm best-practice guide:
  fullname    = <release>-<chart>  (capped at 63 chars)
  chart       = <chart>-<version>
  labels      = standard Helm recommended labels
  selectorLabels = labels safe for use in matchLabels (immutable after creation)
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "wslvault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 characters because Kubernetes DNS labels have this limit.
If release name already contains the chart name it is used as-is.
*/}}
{{- define "wslvault.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create a fully qualified name for a specific component (e.g. "crypto-service").
Usage: {{ include "wslvault.componentFullname" (dict "component" "crypto-service" "context" $) }}
*/}}
{{- define "wslvault.componentFullname" -}}
{{- printf "%s-%s" (include "wslvault.fullname" .context) .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart label value: <name>-<version>.
*/}}
{{- define "wslvault.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource managed by this chart.
These labels enable standard tooling (Helm, kubectl, Prometheus) to identify resources.
*/}}
{{- define "wslvault.labels" -}}
helm.sh/chart: {{ include "wslvault.chart" . }}
{{ include "wslvault.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels: stable subset of labels used in matchLabels.
IMPORTANT: These must NOT change after a Deployment is created because
matchLabels is immutable. Only add new selectors here with caution.
*/}}
{{- define "wslvault.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wslvault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-specific labels.
Usage: {{ include "wslvault.componentLabels" (dict "component" "crypto-service" "context" $) }}
*/}}
{{- define "wslvault.componentLabels" -}}
helm.sh/chart: {{ include "wslvault.chart" .context }}
app.kubernetes.io/name: {{ .component }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
{{- if .context.Chart.AppVersion }}
app.kubernetes.io/version: {{ .context.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .context.Release.Service }}
app.kubernetes.io/part-of: {{ include "wslvault.name" .context }}
app.kubernetes.io/component: {{ .componentType | default "core" }}
{{- end }}

{{/*
Component selector labels (stable, used in matchLabels).
Usage: {{ include "wslvault.componentSelectorLabels" (dict "component" "crypto-service" "context" $) }}
*/}}
{{- define "wslvault.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ .component }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
{{- end }}

{{/*
Resolve the service account name.
If serviceAccount.create=true and serviceAccount.name is set, use that name.
If serviceAccount.create=true and name is empty, use the chart fullname.
If serviceAccount.create=false, use the provided name or "default".
*/}}
{{- define "wslvault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "wslvault.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Build the PostgreSQL host.
When postgresql.enabled=true the Bitnami subchart creates a service named
"<release>-postgresql" on port 5432.  When disabled, fall back to the
postgresql.external.host value supplied by the operator.
*/}}
{{- define "wslvault.postgresHost" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- required "postgresql.external.host is required when postgresql.enabled=false" .Values.postgresql.external.host }}
{{- end }}
{{- end }}

{{/*
Build the PostgreSQL port.
*/}}
{{- define "wslvault.postgresPort" -}}
{{- if .Values.postgresql.enabled }}
{{- print "5432" }}
{{- else }}
{{- default "5432" .Values.postgresql.external.port | toString }}
{{- end }}
{{- end }}

{{/*
Build the full DATABASE_URL environment variable value.
Format: postgresql://<user>:<password>@<host>:<port>/<database>
The password is embedded from postgresql.auth.password. Ensure the password
is URL-safe (no @ / : characters) or url-encode it before supplying.
*/}}
{{- define "wslvault.databaseURL" -}}
{{- printf "postgresql://%s:%s@%s:%s/%s"
    .Values.postgresql.auth.username
    .Values.postgresql.auth.password
    (include "wslvault.postgresHost" .)
    (include "wslvault.postgresPort" .)
    .Values.postgresql.auth.database }}
{{- end }}

{{/*
Image reference helper.
Returns "<repository>:<tag>" using the per-service tag if set, otherwise
falling back to global.imageTag.
Usage: {{ include "wslvault.image" (dict "image" .Values.cryptoService.image "context" $) }}
*/}}
{{- define "wslvault.image" -}}
{{- $tag := .image.tag | default .context.Values.global.imageTag }}
{{- printf "%s:%s" .image.repository $tag }}
{{- end }}

{{/*
Standard security context for all wslvault microservice containers.
All services run as the nobody user (65534) with a read-only root filesystem.
Capabilities are dropped entirely to follow the principle of least privilege.
*/}}
{{- define "wslvault.containerSecurityContext" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
{{- end }}

{{/*
Standard pod security context.
*/}}
{{- define "wslvault.podSecurityContext" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  fsGroup: 65534
{{- end }}

{{/*
Pod scheduling (nodeSelector / affinity / tolerations) for a component.
Renders the per-service values when set, otherwise falls back to the
cluster-wide defaults under global.scheduling. This is what pins every
workload in the release to a single node: change
global.scheduling.nodeSelector in values.yaml and the whole stack follows.
Usage: {{ include "wslvault.podScheduling" (dict "service" .Values.auditService "context" $) | nindent 6 }}
*/}}
{{- define "wslvault.podScheduling" -}}
{{- $global := .context.Values.global.scheduling | default dict }}
{{- $svc := .service | default dict }}
{{- with (default $global.nodeSelector $svc.nodeSelector) }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default $global.affinity $svc.affinity) }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default $global.tolerations $svc.tolerations) }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Resolve the name of the DB credentials secret.
When postgresql.auth.existingSecret is set, that secret is used directly.
Otherwise the chart-managed "wslvault-db-credentials" secret is used.
*/}}
{{- define "wslvault.dbCredentialsSecretName" -}}
{{- if .Values.postgresql.auth.existingSecret }}
{{- .Values.postgresql.auth.existingSecret }}
{{- else }}
{{- printf "%s-db-credentials" (include "wslvault.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Resolve the password key inside the DB credentials secret.
*/}}
{{- define "wslvault.dbPasswordSecretKey" -}}
{{- if .Values.postgresql.auth.existingSecret }}
{{- .Values.postgresql.auth.secretKeys.userPasswordKey | default "password" }}
{{- else }}
{{- print "password" }}
{{- end }}
{{- end }}

{{/*
────────────────────────────────────────────────────────────────────────────
Multi-region helpers.

A "region" is one complete, self-contained wslvault release: its own Postgres,
its own service set, its own public edge hostname. Two or more regions form the
HA mesh, kept in sync by each region's replication-agent polling every peer's
/v1/replication/events endpoint over the public edge. Peering MUST go over
public URLs: edge PoP nodes carry network.k3s1/cross-node=unavailable, so pods
in one region have no pod-network route to pods in another.
────────────────────────────────────────────────────────────────────────────
*/}}

{{/*
The region identity for this release.
Every replication row, vector-clock entry and system.regions key is stamped
with this, so it MUST be stable for the life of the region and unique across
the mesh. Changing it on a live region orphans that region's replication state.
*/}}
{{- define "wslvault.regionId" -}}
{{- required "global.region.id is required (a stable, mesh-unique region identifier, e.g. \"region-a\")" .Values.global.region.id }}
{{- end }}

{{/*
Human-readable region name, defaulting to the id.
*/}}
{{- define "wslvault.regionDisplayName" -}}
{{- .Values.global.region.displayName | default (include "wslvault.regionId" .) }}
{{- end }}

{{/*
This region's own externally reachable base URL, as peers should address it.
Defaults to https://<edgeIngress.host> when not set explicitly.
*/}}
{{- define "wslvault.regionEndpoint" -}}
{{- if .Values.global.region.endpoint }}
{{- .Values.global.region.endpoint }}
{{- else }}
{{- printf "https://%s" (required "set global.region.endpoint, or edgeIngress.host to derive it" .Values.edgeIngress.host) }}
{{- end }}
{{- end }}

{{/*
REPLICATION_PEERS value: comma-separated "<region_id>=<url>" pairs, the format
parsed by services/replication-agent/src/config.rs. The local region is
filtered out of the list so one identical peer roster can be shared verbatim by
every region's values file.
*/}}
{{- define "wslvault.replicationPeers" -}}
{{- $local := include "wslvault.regionId" . }}
{{- $pairs := list }}
{{- range .Values.global.region.peers }}
{{- if ne .id $local }}
{{- $pairs = append $pairs (printf "%s=%s" .id (required (printf "global.region.peers entry %q needs a replicationUrl" .id) .replicationUrl)) }}
{{- end }}
{{- end }}
{{- join "," $pairs }}
{{- end }}

{{/*
────────────────────────────────────────────────────────────────────────────
Shared-key secret resolution.

The root key, JWT secret and PKI root key MUST be byte-identical across every
region in the mesh: replicated ciphertext is decrypted with the receiving
region's root key, and a token minted in one region is verified in another. Set
secrets.existingSecret to a Secret provisioned out-of-band (SealedSecret,
ExternalSecret, …) so the same material reaches every region without ever
living in Git.
────────────────────────────────────────────────────────────────────────────
*/}}

{{- define "wslvault.rootKeySecretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-root-key" (include "wslvault.fullname" .)) }}
{{- end }}

{{- define "wslvault.rootKeySecretKey" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecretKeys.rootKey | default "root-key" }}
{{- else }}
{{- print "root-key" }}
{{- end }}
{{- end }}

{{- define "wslvault.jwtSecretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-jwt-secret" (include "wslvault.fullname" .)) }}
{{- end }}

{{- define "wslvault.jwtSecretKey" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecretKeys.jwtSecret | default "jwt-secret" }}
{{- else }}
{{- print "jwt-secret" }}
{{- end }}
{{- end }}

{{- define "wslvault.pkiRootKeySecretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-pki-root-key" (include "wslvault.fullname" .)) }}
{{- end }}

{{- define "wslvault.pkiRootKeySecretKey" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecretKeys.pkiRootKey | default "pki-root-key" }}
{{- else }}
{{- print "pki-root-key" }}
{{- end }}
{{- end }}

{{/*
Environment block shared by the region-aware services (replication-agent and
region-health). REGION_ID used to come from a downward-API fieldRef on the
`topology.kubernetes.io/region` pod label — a label this chart never sets, so
it always resolved to the empty string and every region called itself "".
It is templated from values now.
*/}}
{{- define "wslvault.regionEnv" -}}
- name: REGION_ID
  value: {{ include "wslvault.regionId" . | quote }}
- name: REGION_ENDPOINT
  value: {{ include "wslvault.regionEndpoint" . | quote }}
{{- end }}

{{/*
Content hash of everything the migrations Job acts on. The Job is a plain
(non-hook) resource whose name carries this hash, so it is immutable and
re-runs exactly when the SQL or the region registry changes — not on every
unrelated `helm upgrade`.
*/}}
{{- define "wslvault.migrationsHash" -}}
{{- $sql := "" }}
{{- range $path, $_ := .Files.Glob "files/migrations/*.sql" }}
{{- $sql = printf "%s%s" $sql ($.Files.Get $path) }}
{{- end }}
{{- printf "%s%s" $sql (toYaml .Values.global.region) | sha256sum | trunc 8 }}
{{- end }}

{{/*
Render a value as a PostgreSQL string literal.
`quote` produces DOUBLE quotes, which PostgreSQL parses as an identifier — a
region id rendered that way fails with `column "region-a" does not exist`.
Embedded single quotes are doubled so a value cannot terminate the literal.
Usage: {{ include "wslvault.sqlLiteral" .Values.global.region.id }}
*/}}
{{- define "wslvault.sqlLiteral" -}}
{{- printf "'%s'" (. | toString | replace "'" "''") }}
{{- end }}

{{/*
Shared replication peer token. Like the crypto keys, this MUST be identical in
every region: each region authenticates to its peers with it and validates its
peers against it. It lives in the same out-of-band mesh Secret.
*/}}
{{- define "wslvault.peerTokenSecretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-replication-peer-token" (include "wslvault.fullname" .)) }}
{{- end }}

{{- define "wslvault.peerTokenSecretKey" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecretKeys.replicationPeerToken | default "replication-peer-token" }}
{{- else }}
{{- print "replication-peer-token" }}
{{- end }}
{{- end }}
