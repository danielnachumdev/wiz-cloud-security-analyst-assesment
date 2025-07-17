package scripts

import rego.v1

default match := false

safe_tcp_ports := [22, 53, 135, 443, 445, 563, 993]

is_valid(rule) if {
	rule.IpProtocol == "icmp"
	rule.FromPort == rule.ToPort
	rule.FromPort in safe_tcp_ports
}

is_valid(rule) if {
	rule.IpProtocol == "tcp"
}

is_rule_safe(rule) if {
	rule.FromPort < 1024
	rule.ToPort < 1024
	is_valid(rule)
}

is_inbound_rules_unsafe(sg) if {
	some rule in sg.IpPermissions
	not is_rule_safe(rule)
}

match if {
	some sg in input.SecurityGroups
	is_inbound_rules_unsafe(sg)
}
