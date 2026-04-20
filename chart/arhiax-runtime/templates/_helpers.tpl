{{/*
=============================================================================
ARHIAX Runtime - Named template helpers
=============================================================================
All reusable template logic lives here. Every resource template in this
chart consumes these helpers for naming, labeling, and service account
resolution. Keep this file consistent with values.yaml.
=============================================================================
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "arhiax.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to that.
If release name contains chart name it will be used as a full name.
*/}}
{{- define "arhiax.fullname" -}}
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
Chart name and version as used by the chart label.
*/}}
{{- define "arhiax.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels applied to every resource.
*/}}
{{- define "arhiax.labels" -}}
helm.sh/chart: {{ include "arhiax.chart" . }}
{{ include "arhiax.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: arhiax
{{- with .Values.global.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Selector labels (stable across upgrades - do NOT include version here).
*/}}
{{- define "arhiax.selectorLabels" -}}
app.kubernetes.io/name: {{ include "arhiax.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Common annotations applied to every resource.
*/}}
{{- define "arhiax.annotations" -}}
{{- with .Values.global.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Return the proper image registry, repository, and tag.
Usage: {{ include "arhiax.image" (dict "image" .Values.gateway.image "global" .Values.global) }}
*/}}
{{- define "arhiax.image" -}}
{{- $registry := .image.registry -}}
{{- if .global.imageRegistry -}}
{{- $registry = .global.imageRegistry -}}
{{- end -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry .image.repository .image.tag -}}
{{- else -}}
{{- printf "%s:%s" .image.repository .image.tag -}}
{{- end -}}
{{- end -}}

{{/*
Return merged imagePullSecrets from global + component.
Usage: {{ include "arhiax.imagePullSecrets" (dict "image" .Values.gateway.image "global" .Values.global) }}
*/}}
{{- define "arhiax.imagePullSecrets" -}}
{{- $secrets := list -}}
{{- range .global.imagePullSecrets -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- range .image.pullSecrets -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- if $secrets -}}
imagePullSecrets:
{{- range $secrets }}
  - name: {{ . }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Return the storage class name, honoring global override.
Usage: {{ include "arhiax.storageClass" (dict "persistence" .Values.evidenceStore.persistence "global" .Values.global) }}
*/}}
{{- define "arhiax.storageClass" -}}
{{- if .persistence.storageClass -}}
{{- .persistence.storageClass -}}
{{- else if .global.storageClass -}}
{{- .global.storageClass -}}
{{- end -}}
{{- end -}}

{{/*
=============================================================================
Gateway helpers
=============================================================================
*/}}

{{- define "arhiax.gateway.fullname" -}}
{{- printf "%s-gateway" (include "arhiax.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "arhiax.gateway.labels" -}}
{{ include "arhiax.labels" . }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "arhiax.gateway.selectorLabels" -}}
{{ include "arhiax.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "arhiax.gateway.serviceAccountName" -}}
{{- if .Values.gateway.serviceAccount.create -}}
{{- default (include "arhiax.gateway.fullname" .) .Values.gateway.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.gateway.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
=============================================================================
OPA helpers
=============================================================================
*/}}

{{- define "arhiax.opa.fullname" -}}
{{- printf "%s-opa" (include "arhiax.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "arhiax.opa.labels" -}}
{{ include "arhiax.labels" . }}
app.kubernetes.io/component: opa
{{- end -}}

{{- define "arhiax.opa.selectorLabels" -}}
{{ include "arhiax.selectorLabels" . }}
app.kubernetes.io/component: opa
{{- end -}}

{{- define "arhiax.opa.serviceAccountName" -}}
{{- if .Values.opa.serviceAccount.create -}}
{{- default (include "arhiax.opa.fullname" .) .Values.opa.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.opa.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Returns the OPA service URL for in-cluster consumption by the gateway.
*/}}
{{- define "arhiax.opa.url" -}}
{{- if .Values.gateway.config.opaUrl -}}
{{- .Values.gateway.config.opaUrl -}}
{{- else -}}
{{- printf "http://%s.%s.svc.%s:%d" (include "arhiax.opa.fullname" .) .Release.Namespace .Values.global.clusterDomain (int .Values.opa.service.port) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the ConfigMap holding Rego bundles.
*/}}
{{- define "arhiax.opa.bundleConfigMapName" -}}
{{- if .Values.opa.bundleConfigMap.existingConfigMap -}}
{{- .Values.opa.bundleConfigMap.existingConfigMap -}}
{{- else -}}
{{- printf "%s-bundles" (include "arhiax.opa.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Name of the ConfigMap holding OPA's own config.yaml.
*/}}
{{- define "arhiax.opa.configMapName" -}}
{{- printf "%s-config" (include "arhiax.opa.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
=============================================================================
Evidence Store helpers
=============================================================================
*/}}

{{- define "arhiax.evidenceStore.fullname" -}}
{{- printf "%s-evidence-store" (include "arhiax.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "arhiax.evidenceStore.labels" -}}
{{ include "arhiax.labels" . }}
app.kubernetes.io/component: evidence-store
{{- end -}}

{{- define "arhiax.evidenceStore.selectorLabels" -}}
{{ include "arhiax.selectorLabels" . }}
app.kubernetes.io/component: evidence-store
{{- end -}}

{{- define "arhiax.evidenceStore.serviceAccountName" -}}
{{- if .Values.evidenceStore.serviceAccount.create -}}
{{- default (include "arhiax.evidenceStore.fullname" .) .Values.evidenceStore.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.evidenceStore.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Returns the evidence store URL for in-cluster consumption.
*/}}
{{- define "arhiax.evidenceStore.url" -}}
{{- if .Values.gateway.config.evidenceStoreUrl -}}
{{- .Values.gateway.config.evidenceStoreUrl -}}
{{- else -}}
{{- printf "http://%s.%s.svc.%s:%d" (include "arhiax.evidenceStore.fullname" .) .Release.Namespace .Values.global.clusterDomain (int .Values.evidenceStore.service.port) -}}
{{- end -}}
{{- end -}}

{{/*
PVC name for the evidence store (honors existingClaim).
*/}}
{{- define "arhiax.evidenceStore.pvcName" -}}
{{- if .Values.evidenceStore.persistence.existingClaim -}}
{{- .Values.evidenceStore.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "arhiax.evidenceStore.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
=============================================================================
Validation - fail fast on incompatible value combinations
=============================================================================
*/}}
{{- define "arhiax.validateValues" -}}
{{- if and (eq .Values.opa.bundleSource.mode "server") (not .Values.opa.bundleServer.enabled) -}}
{{- fail "opa.bundleSource.mode=server requires opa.bundleServer.enabled=true" -}}
{{- end -}}
{{- if and (eq .Values.opa.bundleSource.mode "configmap") (not .Values.opa.bundleConfigMap.create) (not .Values.opa.bundleConfigMap.existingConfigMap) -}}
{{- fail "opa.bundleSource.mode=configmap requires either bundleConfigMap.create=true or bundleConfigMap.existingConfigMap to be set" -}}
{{- end -}}
{{- if and (eq .Values.evidenceStore.driver "postgres") (not .Values.evidenceStore.postgres.host) -}}
{{- fail "evidenceStore.driver=postgres requires evidenceStore.postgres.host to be set" -}}
{{- end -}}
{{- if and (eq .Values.evidenceStore.driver "postgres") (not .Values.evidenceStore.postgres.existingSecret) -}}
{{- fail "evidenceStore.driver=postgres requires evidenceStore.postgres.existingSecret to be set" -}}
{{- end -}}
{{- end -}}
