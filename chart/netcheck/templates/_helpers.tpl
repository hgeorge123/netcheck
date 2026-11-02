{{- define "netcheck.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Namespace where NetCheck runs: namespace.name, or the Helm release namespace. */}}
{{- define "netcheck.namespace" -}}
{{- .Values.namespace.name | default .Release.Namespace -}}
{{- end -}}

{{- define "netcheck.selectorLabels" -}}
app.kubernetes.io/name: netcheck
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "netcheck.labels" -}}
{{ include "netcheck.selectorLabels" . }}
app.kubernetes.io/part-of: netcheck
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "netcheck.serviceAccountName" -}}
{{ include "netcheck.fullname" . }}-controller
{{- end -}}

{{- define "netcheck.controllerUser" -}}
system:serviceaccount:{{ include "netcheck.namespace" . }}:{{ include "netcheck.serviceAccountName" . }}
{{- end -}}

{{/* repo:tag@digest when pinned: the tag is informative, the digest wins. */}}
{{- define "netcheck.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}{{ with .Values.image.tag }}:{{ . }}{{ end }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "netcheck.probeImage" -}}
{{ .Values.probeImage.repository }}{{ with .Values.probeImage.tag }}:{{ . }}{{ end }}@{{ .Values.probeImage.digest }}
{{- end -}}

{{- define "netcheck.bootstrapSecretName" -}}
{{- .Values.auth.bootstrapAdmin.existingSecret | default (printf "%s-bootstrap-admin" (include "netcheck.fullname" .)) -}}
{{- end -}}

{{- define "netcheck.storageClassName" -}}
{{- if .Values.persistence.storageClassName -}}
{{ .Values.persistence.storageClassName }}
{{- else if .Values.persistence.createStorageClass.enabled -}}
{{ .Values.persistence.createStorageClass.name }}
{{- end -}}
{{- end -}}

{{/* Namespaces where probes may never run (JSON list for CEL). The NetCheck
     namespace is not listed: the app only uses it for users explicitly
     allowed to (per-user checkbox). */}}
{{- define "netcheck.excludedNamespaces" -}}
{{- $ex := list "kube-system" "kube-public" "kube-node-lease" "default" -}}
{{- range .Values.namespaceScope.exclude -}}{{- $ex = append $ex . -}}{{- end -}}
{{- $ex | uniq | toJson -}}
{{- end -}}

{{/* Namespaces of the Gateway data plane allowed by the NetworkPolicy. */}}
{{- define "netcheck.gatewayNamespaces" -}}
{{- $ns := .Values.networkPolicy.gatewayNamespaces -}}
{{- if not $ns -}}
{{- range .Values.httpRoute.parentRefs -}}{{- $ns = append $ns (.namespace | default (include "netcheck.namespace" $)) -}}{{- end -}}
{{- end -}}
{{- $ns | uniq | toJson -}}
{{- end -}}

{{/* Fails rendering on unsafe, incomplete or unsupported combinations. */}}
{{- define "netcheck.validate" -}}
{{- $v := .Values -}}
{{- if not (has $v.environment (list "development" "production")) -}}
{{- fail "environment must be development or production" -}}
{{- end -}}
{{- if not $v.image.repository -}}
{{- fail "image.repository is required" -}}
{{- end -}}
{{- if and (eq $v.environment "production") (not (regexMatch "^sha256:[a-f0-9]{64}$" $v.image.digest)) -}}
{{- fail "image.digest (sha256:...) is required in production" -}}
{{- end -}}
{{- if not $v.probeImage.repository -}}
{{- fail "probeImage.repository is required" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $v.probeImage.digest) -}}
{{- fail "probeImage.digest must be a sha256 digest" -}}
{{- end -}}
{{- range $name, $tag := dict "image.tag" $v.image.tag "probeImage.tag" ($v.probeImage.tag | default "") -}}
{{- if and $tag (not (regexMatch "^[a-z0-9_][a-z0-9_.-]{0,127}$" $tag)) -}}
{{- fail (printf "%s must be a lowercase image tag such as 0.2.2" $name) -}}
{{- end -}}
{{- end -}}
{{- if ne $v.environment "development" -}}
{{- if not $v.auth.cookieSecure -}}{{- fail "auth.cookieSecure=false is only allowed in development" -}}{{- end -}}
{{- if not $v.auth.bootstrapAdmin.forcePasswordChange -}}{{- fail "auth.bootstrapAdmin.forcePasswordChange=false is only allowed in development" -}}{{- end -}}
{{- end -}}
{{- if not (has $v.namespaceScope.mode (list "all" "list")) -}}
{{- fail "namespaceScope.mode must be all or list" -}}
{{- end -}}
{{- if and (eq $v.namespaceScope.mode "list") (not $v.namespaceScope.namespaces) -}}
{{- fail "namespaceScope.namespaces must list at least one namespace in list mode" -}}
{{- end -}}
{{- if and (eq $v.namespaceScope.mode "all") $v.namespaceScope.namespaces -}}
{{- fail "namespaceScope.namespaces must be empty in all mode (use namespaceScope.exclude)" -}}
{{- end -}}
{{- range $v.namespaceScope.namespaces -}}
{{- if has . (list "kube-system" "kube-public" "kube-node-lease" "default" (include "netcheck.namespace" $)) -}}
{{- fail (printf "namespace %s is not allowed as probe source" .) -}}
{{- end -}}
{{- end -}}
{{- if not $v.destinations.allowCidrs -}}
{{- fail "destinations.allowCidrs is empty: every test would be denied. List the networks users may test (e.g. the VPC CIDR)" -}}
{{- end -}}
{{- if not $v.destinations.allowPorts -}}
{{- fail "destinations.allowPorts is empty: every TCP/HTTP test would be denied" -}}
{{- end -}}
{{- if and $v.networkPolicy.enabled (not $v.networkPolicy.apiServer.cidrs) -}}
{{- fail "networkPolicy.apiServer.cidrs is required when networkPolicy.enabled (the controller needs the Kubernetes API server)" -}}
{{- end -}}
{{- if and (not (include "netcheck.storageClassName" .)) (not $v.persistence.existingClaim) -}}
{{- fail "set persistence.storageClassName, persistence.createStorageClass.enabled or persistence.existingClaim" -}}
{{- end -}}
{{- if not (has $v.destinationsManagedBy (list "ui" "helm")) -}}
{{- fail "destinationsManagedBy must be ui (edited in the web) or helm (these values are authoritative)" -}}
{{- end -}}
{{- if and $v.httpRoute.enabled $v.ingress.enabled -}}
{{- fail "httpRoute.enabled and ingress.enabled are mutually exclusive: choose NGINX Gateway Fabric (httpRoute) or the AWS Load Balancer Controller (ingress). To use the ALB set httpRoute.enabled=false" -}}
{{- end -}}
{{- if $v.ingress.enabled -}}
{{- if not $v.ingress.hosts -}}{{- fail "ingress.hosts is required when ingress.enabled (e.g. [netcheck.example.com])" -}}{{- end -}}
{{- if not (has $v.ingress.alb.scheme (list "internal" "internet-facing")) -}}{{- fail "ingress.alb.scheme must be internal or internet-facing" -}}{{- end -}}
{{- if not $v.ingress.alb.certificateArns -}}
{{- fail "ingress.alb.certificateArns is required when ingress.enabled: the ALB must terminate HTTPS with an ACM certificate (login passwords travel through it)" -}}
{{- end -}}
{{- range $v.ingress.alb.certificateArns -}}
{{- if not (hasPrefix "arn:aws" .) -}}{{- fail (printf "ingress.alb.certificateArns: %q is not an ACM certificate ARN" .) -}}{{- end -}}
{{- end -}}
{{- if not $v.auth.trustedProxyCidrs -}}
{{- fail "auth.trustedProxyCidrs is required with ingress (CIDR of the ALB subnets, usually the VPC CIDR); without it all users share one login rate limit" -}}
{{- end -}}
{{- if and $v.networkPolicy.enabled (not $v.networkPolicy.loadBalancerCidrs) -}}
{{- fail "networkPolicy.loadBalancerCidrs is required when networkPolicy.enabled and ingress.enabled (CIDRs of the ALB subnets)" -}}
{{- end -}}
{{- end -}}
{{- if $v.httpRoute.enabled -}}
{{- if not $v.httpRoute.hostnames -}}{{- fail "httpRoute.hostnames is required when httpRoute.enabled" -}}{{- end -}}
{{- if not $v.httpRoute.parentRefs -}}{{- fail "httpRoute.parentRefs is required when httpRoute.enabled (your existing Gateway)" -}}{{- end -}}
{{- range $v.httpRoute.parentRefs -}}
{{- if or (not .name) (not .sectionName) -}}
{{- fail "every httpRoute.parentRefs entry needs name and sectionName (the HTTPS listener: login passwords travel over this route)" -}}
{{- end -}}
{{- end -}}
{{- if not $v.auth.trustedProxyCidrs -}}
{{- fail "auth.trustedProxyCidrs is required with httpRoute (CIDR of the Gateway data plane Pods, usually the VPC CIDR); without it all users share one login rate limit" -}}
{{- end -}}
{{- if not ($.Capabilities.APIVersions.Has "gateway.networking.k8s.io/v1/HTTPRoute") -}}
{{- fail "the cluster has no Gateway API (gateway.networking.k8s.io/v1 HTTPRoute). Install the Gateway API CRDs / NGINX Gateway Fabric first" -}}
{{- end -}}
{{- end -}}
{{- /* ValidatingAdmissionPolicy v1 (GA in 1.30) is guaranteed by kubeVersion in Chart.yaml. */ -}}
{{- include "netcheck.preflight" . -}}
{{- end -}}

{{/* Cluster checks. lookup only returns data when Helm talks to a cluster
     (install/upgrade, or --dry-run=server); `helm template` skips them. */}}
{{- define "netcheck.preflight" -}}
{{- $v := .Values -}}
{{- $connected := lookup "v1" "Namespace" "" "kube-system" -}}
{{- if and $v.preflight.enabled $connected -}}
{{- if $v.preflight.vpcCniNetworkPolicy -}}
{{- $ds := lookup "apps/v1" "DaemonSet" "kube-system" "aws-node" -}}
{{- if not $ds -}}
{{- fail "preflight: DaemonSet kube-system/aws-node not found. NetCheck expects Amazon VPC CNI; set preflight.vpcCniNetworkPolicy=false only if you use another CNI that enforces NetworkPolicy" -}}
{{- end -}}
{{- $enabled := false -}}
{{- range $ds.spec.template.spec.containers -}}
{{- range (.args | default list) -}}{{- if eq . "--enable-network-policy=true" -}}{{- $enabled = true -}}{{- end -}}{{- end -}}
{{- end -}}
{{- if not $enabled -}}
{{- fail "preflight: VPC CNI network policy is disabled (aws-node has no --enable-network-policy=true). Enable it in the vpc-cni addon (enableNetworkPolicy: \"true\"), otherwise NetworkPolicies are not enforced and results would be misleading" -}}
{{- end -}}
{{- end -}}
{{- if and $v.preflight.ebsCsiDriver $v.persistence.createStorageClass.enabled (not $v.persistence.storageClassName) (not $v.persistence.existingClaim) -}}
{{- if not (lookup "storage.k8s.io/v1" "CSIDriver" "" "ebs.csi.aws.com") -}}
{{- fail "preflight: CSIDriver ebs.csi.aws.com not found. Install the aws-ebs-csi-driver EKS addon (with its IAM role) before NetCheck" -}}
{{- end -}}
{{- end -}}
{{- if $v.persistence.storageClassName -}}
{{- if not (lookup "storage.k8s.io/v1" "StorageClass" "" $v.persistence.storageClassName) -}}
{{- fail (printf "preflight: StorageClass %s not found" $v.persistence.storageClassName) -}}
{{- end -}}
{{- end -}}
{{- if and $v.preflight.gateway $v.httpRoute.enabled -}}
{{- range $v.httpRoute.parentRefs -}}
{{- if not (lookup "gateway.networking.k8s.io/v1" "Gateway" (.namespace | default (include "netcheck.namespace" $)) .name) -}}
{{- fail (printf "preflight: Gateway %s/%s not found" (.namespace | default (include "netcheck.namespace" $)) .name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and $v.preflight.ingressClass $v.ingress.enabled -}}
{{- $ic := lookup "networking.k8s.io/v1" "IngressClass" "" $v.ingress.className -}}
{{- if not $ic -}}
{{- fail (printf "preflight: IngressClass %s not found. Install the AWS Load Balancer Controller (with its IAM role) first" $v.ingress.className) -}}
{{- end -}}
{{- if ne $ic.spec.controller "ingress.k8s.aws/alb" -}}
{{- fail (printf "preflight: IngressClass %s belongs to %s, not to the AWS Load Balancer Controller (ingress.k8s.aws/alb)" $v.ingress.className $ic.spec.controller) -}}
{{- end -}}
{{- end -}}
{{- if eq $v.namespaceScope.mode "list" -}}
{{- range $v.namespaceScope.namespaces -}}
{{- if not (lookup "v1" "Namespace" "" .) -}}
{{- fail (printf "preflight: namespace %s does not exist" .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
