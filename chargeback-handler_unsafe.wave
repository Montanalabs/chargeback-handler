#! VULNERABLE chargeback-handler — feeds the untrusted input straight to the tool with no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant handle

let dispute = fetch<web>
privileged { handle(dispute) }  # tainted -> tool: REJECTED
