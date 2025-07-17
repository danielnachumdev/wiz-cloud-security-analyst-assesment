# Namespace for this policy to avoid name collisions with other policies/rules.
package ec2policy

# By default, the 'match' key will be false unless another rule sets it to true.
default match = false

# This rule sets 'match' to true if the condition inside the block is satisfied:
# Specifically, if the 'HttpTokens' field in the input JSON has the value "optional".
match {
    input.HttpTokens == "optional"
}