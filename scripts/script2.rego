package example.security_groups

import rego.v1

default match := false

# all ipv4 ip for any protocol
case1_egress(sg) if {
	count(sg.IpPermissionsEgress) == 1
	rule := sg.IpPermissionsEgress[0]
	rule.IpProtocol == "-1"
    not rule.ToPort
    not rule.FromPort
	count(rule.IpRanges) == 1
	rule.IpRanges[0].CidrIp == "0.0.0.0/0"
	count(rule.UserIdGroupPairs) == 0
	count(rule.Ipv6Ranges) == 0
	count(rule.PrefixListIds) == 0
}

# all ipv4 ips for SMP protocol
case1_ingress(sg) if {
	count(sg.IpPermissions) == 1
	rule := sg.IpPermissions[0]
	rule.IpProtocol == "tcp"
	rule.FromPort == 445
	rule.ToPort == 445
	count(rule.IpRanges) == 1
	endswith(rule.IpRanges[0].CidrIp, "/32") # only one IPv4 address allowed
	count(rule.UserIdGroupPairs) == 0
	count(rule.Ipv6Ranges) == 0
	count(rule.PrefixListIds) == 0
}

case1(sg) if {
	case1_ingress(sg)
	case1_egress(sg)
}

# no outbound rules allowed
case2_egress(sg) if {
	count(sg.IpPermissionsEgress) == 0
}

case2_IMAPS(rule) if {
	rule.IpProtocol == "tcp"
	rule.FromPort == 993
	rule.ToPort == 993
	count(rule.UserIdGroupPairs) == 0
	count(rule.IpRanges) == 0
	count(rule.Ipv6Ranges) == 1
	rule.Ipv6Ranges[0].CidrIpv6 == "::/0"
	count(rule.PrefixListIds) == 0
}

case2_LDAP(rule) if {
	rule.IpProtocol == "tcp"
	rule.FromPort == 389
	rule.ToPort == 389
	count(rule.UserIdGroupPairs) == 0
	count(rule.IpRanges) == 1
	rule.IpRanges[0].CidrIp == "0.0.0.0/0"
	count(rule.Ipv6Ranges) == 0
	count(rule.PrefixListIds) == 0
}

case2_ingress(sg) if {
	count(sg.IpPermissions) == 2
	case2_IMAPS(sg.IpPermissions[0])
	case2_LDAP(sg.IpPermissions[1])
}

case2(sg) if {
	case2_ingress(sg)
	case2_egress(sg)
}

case3_ingress(sg) if {
    count(sg.IpPermissionsEgress) == 1
    rule := sg.IpPermissionsEgress[0]
    rule.IpProtocol == "-1"
    count(rule.IpRanges) == 1
    rule.IpRanges[0].CidrIp == "0.0.0.0/0"
    count(rule.UserIdGroupPairs) == 0
    count(rule.Ipv6Ranges) == 1
    not rule.ToPort
    not rule.FromPort
    rule.Ipv6Ranges[0].CidrIpv6 == "::/0"
    count(rule.PrefixListIds) == 0
}
case3_egress(sg) if {
    count(sg.IpPermissions) == 0
}
case3(sg) if {
    case3_ingress(sg)
    case3_egress(sg)
}

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

match := is_unsafe
