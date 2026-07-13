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
