{{/* Common labels applied to every resource. */}}
{{- define "miraige.labels" -}}
app.kubernetes.io/part-of: miraige
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* A compose service key (may contain "_") → a DNS-1035 k8s Service name. */}}
{{- define "miraige.svcName" -}}
{{- . | replace "_" "-" -}}
{{- end -}}
