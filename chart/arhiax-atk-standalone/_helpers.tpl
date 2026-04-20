{{/*
ARHIAX v11.4 — Helm template helpers
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "arhiax-runtime.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars because some Kubernetes name fields are limited to that.
*/}}
{{- define "arhiax-runtime.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart name + version label
*/}}
{{- define "arhiax-runtime.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every resource.
Includes the mandatory arhiax.* audit labels (preserved from values.yaml).
*/}}
{{- define "arhiax-runtime.labels" -}}
helm.sh/chart: {{ include "arhiax-runtime.chart" . }}
{{ include "arhiax-runtime.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: arhiax
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Selector labels — used in Deployment/Service selectors.
Must remain stable across chart versions (deployment selector is immutable).
*/}}
{{- define "arhiax-runtime.selectorLabels" -}}
app.kubernetes.io/name: {{ include "arhiax-runtime.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Service account name
*/}}
{{- define "arhiax-runtime.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "arhiax-runtime.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Full image reference for the ATK container
*/}}
{{- define "arhiax-runtime.atkImage" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.repository $tag -}}
{{- end -}}

{{/*
Full image reference for the OPA sidecar
*/}}
{{- define "arhiax-runtime.opaImage" -}}
{{- printf "%s/%s:%s" .Values.opa.image.registry .Values.opa.image.repository .Values.opa.image.tag -}}
{{- end -}}

{{/*
ConfigMap name for OPA bundles
*/}}
{{- define "arhiax-runtime.bundlesConfigMapName" -}}
{{- printf "%s-bundles" (include "arhiax-runtime.fullname" .) -}}
{{- end -}}
