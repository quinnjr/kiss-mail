{{/*
Expand the name of the chart.
*/}}
{{- define "kiss-mail.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kiss-mail.fullname" -}}
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
{{- define "kiss-mail.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kiss-mail.labels" -}}
helm.sh/chart: {{ include "kiss-mail.chart" . }}
{{ include "kiss-mail.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kiss-mail.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kiss-mail.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kiss-mail.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kiss-mail.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image name
*/}}
{{- define "kiss-mail.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
PVC name
*/}}
{{- define "kiss-mail.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "kiss-mail.fullname" . }}-data
{{- end }}
{{- end }}

{{/*
Secret name
*/}}
{{- define "kiss-mail.secretName" -}}
{{- include "kiss-mail.fullname" . }}-secrets
{{- end }}

{{/*
SSO environment variable prefix. The binary selects the SSO provider from
provider-specific variables (GOOGLE_*, MICROSOFT_*, OKTA_*, AUTH0_*,
ONEPASSWORD_*); anything else (e.g. "oidc" or "") uses the generic SSO_*
variables.
*/}}
{{- define "kiss-mail.ssoPrefix" -}}
{{- $p := lower (default "" .Values.sso.provider) -}}
{{- if eq $p "google" -}}GOOGLE
{{- else if eq $p "microsoft" -}}MICROSOFT
{{- else if eq $p "okta" -}}OKTA
{{- else if eq $p "auth0" -}}AUTH0
{{- else if eq $p "onepassword" -}}ONEPASSWORD
{{- else -}}SSO
{{- end -}}
{{- end }}

{{/*
KISS_MAIL_TLS from tls.mode: "auto" or "off" (the boolean aliases true/on/yes
and false/no are accepted too, including unquoted YAML booleans).
*/}}
{{- define "kiss-mail.tlsMode" -}}
{{- $m := lower (toString .Values.tls.mode) -}}
{{- if has $m (list "auto" "true" "on" "yes" "1") -}}auto
{{- else if has $m (list "off" "false" "no" "0") -}}off
{{- else -}}{{ fail (printf "tls.mode must be auto or off (got %q)" (toString .Values.tls.mode)) }}
{{- end -}}
{{- end }}

{{/*
"true" when the implicit TLS listeners (smtps/imaps/pop3s) are on.
*/}}
{{- define "kiss-mail.tlsEnabled" -}}
{{- if eq (include "kiss-mail.tlsMode" .) "auto" -}}true{{- end -}}
{{- end }}

{{/*
KISS_MAIL_WEB_SECURE_COOKIE: webAdmin.secureCookie when set, otherwise "true"
only when the Ingress terminates TLS.
*/}}
{{- define "kiss-mail.secureCookie" -}}
{{- $raw := .Values.webAdmin.secureCookie -}}
{{- if kindIs "bool" $raw -}}{{ $raw }}
{{- else if and (not (kindIs "invalid" $raw)) (ne (toString $raw) "") -}}{{ toString $raw }}
{{- else if and .Values.ingress.enabled .Values.ingress.tls -}}true
{{- else -}}false
{{- end -}}
{{- end }}
