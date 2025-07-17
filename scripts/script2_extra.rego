package scripts

import rego.v1

# Default: security group is unsafe unless proven otherwise
default match := false

# Case 1: Egress allows all IPv4 for any protocol
case1_egress(sg) if {
	count(sg.IpPermissionsEgress) == 1
	rule := sg.IpPermissionsEgress[0]
	rule.IpProtocol == "-1"           # Any protocol
	not rule.ToPort                    # No port restrictions
	not rule.FromPort
	count(rule.IpRanges) == 1
	rule.IpRanges[0].CidrIp == "0.0.0.0/0"  # All IPv4
	count(rule.UserIdGroupPairs) == 0
	count(rule.Ipv6Ranges) == 0
	count(rule.PrefixListIds) == 0
}

# Case 1: Ingress allows only one IPv4 address for SMB (port 445)
case1_ingress(sg) if {
	count(sg.IpPermissions) == 1
	rule := sg.IpPermissions[0]
	rule.IpProtocol == "tcp"
	rule.FromPort == 445
	rule.ToPort == 445
	count(rule.IpRanges) == 1
	endswith(rule.IpRanges[0].CidrIp, "/32") # Only one IPv4 address allowed
	count(rule.UserIdGroupPairs) == 0
	count(rule.Ipv6Ranges) == 0
	count(rule.PrefixListIds) == 0
}

# Case 1: Both ingress and egress rules must match
case1(sg) if {
	case1_ingress(sg)
	case1_egress(sg)
}

# Case 2: No outbound rules allowed
case2_egress(sg) if {
	count(sg.IpPermissionsEgress) == 0
}

# Case 2: IMAPS rule (TCP 993, all IPv6)
case2_IMAPS(rule) if {
	rule.IpProtocol == "tcp"
	rule.FromPort == 993
	rule.ToPort == 993
	count(rule.UserIdGroupPairs) == 0
	count(rule.IpRanges) == 0
	count(rule.Ipv6Ranges) == 1
	rule.Ipv6Ranges[0].CidrIpv6 == "::/0"   # All IPv6
	count(rule.PrefixListIds) == 0
}

# Case 2: LDAP rule (TCP 389, all IPv4)
case2_LDAP(rule) if {
	rule.IpProtocol == "tcp"
	rule.FromPort == 389
	rule.ToPort == 389
	count(rule.UserIdGroupPairs) == 0
	count(rule.IpRanges) == 1
	rule.IpRanges[0].CidrIp == "0.0.0.0/0"  # All IPv4
	count(rule.Ipv6Ranges) == 0
	count(rule.PrefixListIds) == 0
}

# Case 2: Ingress must have both IMAPS and LDAP rules
case2_ingress(sg) if {
	count(sg.IpPermissions) == 2
	case2_IMAPS(sg.IpPermissions[0])
	case2_LDAP(sg.IpPermissions[1])
}

# Case 2: Both ingress and egress rules must match
case2(sg) if {
	case2_ingress(sg)
	case2_egress(sg)
}

# Case 3: Ingress allows all IPv4 and all IPv6 for any protocol
case3_ingress(sg) if {
	count(sg.IpPermissionsEgress) == 1
	rule := sg.IpPermissionsEgress[0]
	rule.IpProtocol == "-1"           # Any protocol
	count(rule.IpRanges) == 1
	rule.IpRanges[0].CidrIp == "0.0.0.0/0"  # All IPv4
	count(rule.UserIdGroupPairs) == 0
	count(rule.Ipv6Ranges) == 1
	not rule.ToPort
	not rule.FromPort
	rule.Ipv6Ranges[0].CidrIpv6 == "::/0"   # All IPv6
	count(rule.PrefixListIds) == 0
}

# Case 3: No ingress rules allowed
case3_egress(sg) if {
	count(sg.IpPermissions) == 0
}

# Case 3: Both ingress and egress rules must match
case3(sg) if {
	case3_ingress(sg)
	case3_egress(sg)
}

# A security group is safe if it matches any of the three cases
is_safe_sg(sg) if {
	case1(sg)
}

is_safe_sg(sg) if {
	case2(sg)
}

is_safe_sg(sg) if {
	case3(sg)
}

is_safe if {
	some sg in input.SecurityGroups
	is_safe_sg(sg)
}

is_unsafe if {
	not is_safe
}

# The policy matches if the input is unsafe
match := is_unsafe
