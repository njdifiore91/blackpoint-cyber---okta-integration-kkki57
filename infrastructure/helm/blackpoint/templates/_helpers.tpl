{{/*
Expand the name of the chart.
This template ensures DNS-1123 compliance and proper length restrictions.
*/}}
{{- define "blackpoint.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" | lower | regexReplaceAll "[^-a-z0-9]" "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "blackpoint.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" | lower | regexReplaceAll "[^-a-z0-9]" "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" | lower | regexReplaceAll "[^-a-z0-9]" "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" | lower | regexReplaceAll "[^-a-z0-9]" "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "blackpoint.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels with enhanced security and monitoring context
*/}}
{{- define "blackpoint.labels" -}}
helm.sh/chart: {{ include "blackpoint.chart" . }}
{{ include "blackpoint.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: {{ .Chart.Name }}
security.blackpoint.com/encryption: {{ .Values.global.security.encryption.enabled | quote }}
security.blackpoint.com/key-rotation: {{ .Values.global.security.encryption.keyRotationPeriod }}
monitoring.blackpoint.com/enabled: {{ .Values.global.monitoring.enabled | quote }}
monitoring.blackpoint.com/scrape: {{ .Values.global.monitoring.prometheus.enabled | quote }}
monitoring.blackpoint.com/scrape-interval: {{ .Values.global.monitoring.prometheus.scrapeInterval }}
{{- if .Values.tier }}
tier.blackpoint.com/name: {{ .Values.tier }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "blackpoint.selectorLabels" -}}
app.kubernetes.io/name: {{ include "blackpoint.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "blackpoint.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "blackpoint.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Pod security context with enhanced security settings
*/}}
{{- define "blackpoint.podSecurityContext" -}}
runAsUser: {{ .Values.global.security.runAsUser }}
runAsGroup: {{ .Values.global.security.runAsGroup }}
fsGroup: {{ .Values.global.security.fsGroup }}
runAsNonRoot: {{ .Values.global.security.runAsNonRoot }}
{{- end }}

{{/*
Container security context with enhanced security settings
*/}}
{{- define "blackpoint.containerSecurityContext" -}}
allowPrivilegeEscalation: {{ .Values.global.security.allowPrivilegeEscalation }}
readOnlyRootFilesystem: {{ .Values.global.security.readOnlyRootFilesystem }}
capabilities:
  drop:
  - ALL
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Common annotations with monitoring and security metadata
*/}}
{{- define "blackpoint.annotations" -}}
security.blackpoint.com/last-reviewed: {{ now | date "2006-01-02" | quote }}
monitoring.blackpoint.com/metrics-path: "/metrics"
monitoring.blackpoint.com/metrics-port: "9090"
{{- if .Values.global.monitoring.logging.enabled }}
logging.blackpoint.com/enabled: "true"
logging.blackpoint.com/retention: {{ .Values.global.monitoring.logging.retention | quote }}
{{- end }}
{{- end }}

{{/*
Common environment variables for all components
*/}}
{{- define "blackpoint.commonEnvVars" -}}
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: NODE_NAME
  valueFrom:
    fieldRef:
      fieldPath: spec.nodeName
- name: ENCRYPTION_ENABLED
  value: {{ .Values.global.security.encryption.enabled | quote }}
- name: MONITORING_ENABLED
  value: {{ .Values.global.monitoring.enabled | quote }}
{{- end }}