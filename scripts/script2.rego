package scripts

import rego.v1

default match := false

safe_tcp_ports := [22, 53, 135, 443, 445, 563, 993]



# check if  protocol is icmp OR if protocol tcp and safe port
is_valid(rule) if {
	rule.IpProtocol == "icmp"
	rule.FromPort == rule.ToPort # assuming that this is intended
}
is_valid(rule) if {
	rule.IpProtocol == "tcp"
	rule.FromPort == rule.ToPort # assuming that this is intended
    rule.FromPort in safe_tcp_ports
}

# check if rule is valid and port is lower than 1024
is_rule_safe(rule) if {
	rule.FromPort < 1024
	rule.ToPort < 1024
	is_valid(rule)
}

# if even one rule is unsafe the result is False
is_inbound_rules_unsafe(sg) if {
	some rule in sg.IpPermissions
	not is_rule_safe(rule)
}

# if even one SG has False reutrn True
match if {
	some sg in input.SecurityGroups
	is_inbound_rules_unsafe(sg)
}
