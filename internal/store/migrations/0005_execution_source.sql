-- Where the probe ran, as reported by the Kubernetes API for the probe Pod:
-- its name and the IP of the node (status.hostIP). Shown in the firewall
-- ticket report; traffic leaving the VPC is usually SNATed to the node IP.
ALTER TABLE probe_executions ADD COLUMN pod_name TEXT NOT NULL DEFAULT '';
ALTER TABLE probe_executions ADD COLUMN node_ip TEXT NOT NULL DEFAULT '';
