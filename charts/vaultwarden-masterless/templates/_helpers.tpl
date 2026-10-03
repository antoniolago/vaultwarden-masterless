{{/*
Expand the name of the chart.
*/}}
{{- define "vaultwarden-masterless.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "vaultwarden-masterless.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "vaultwarden-masterless.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vaultwarden-masterless.labels" -}}
helm.sh/chart: {{ include "vaultwarden-masterless.chart" . }}
{{ include "vaultwarden-masterless.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "vaultwarden-masterless.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaultwarden-masterless.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "vaultwarden-masterless.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vaultwarden-masterless.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
RSA secret name for the app's own RSA keys
*/}}
{{- define "vaultwarden-masterless.rsaSecretName" -}}
{{- if .Values.rsaKeys.existingSecret }}
{{- .Values.rsaKeys.existingSecret }}
{{- else }}
{{- printf "%s-rsa" (include "vaultwarden-masterless.fullname" .) }}
{{- end }}
{{- end }}

{{/*
VW RSA public key secret name
*/}}
{{- define "vaultwarden-masterless.vwRsaSecretName" -}}
{{- if .Values.vaultwardenRsaPublicKey.existingSecret }}
{{- .Values.vaultwardenRsaPublicKey.existingSecret }}
{{- else }}
{{- printf "%s-vw-rsa" (include "vaultwarden-masterless.fullname" .) }}
{{- end }}
{{- end }}

{{/*
PVC name
*/}}
{{- define "vaultwarden-masterless.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "vaultwarden-masterless.fullname" .) }}
{{- end }}
{{- end }}
