#! Chargeback handler — untrusted a chargeback dispute can only become one of a fixed set of commands, never a
#! tool argument. An injected instruction cannot be represented in the closed type, so
#! it is rejected at the trust boundary (and re-clamped at run time by extract). The
#! command carries a payload from its own closed set, so even that cannot be smuggled.
#! @requires handle — the dispute-resolution tool
#! @effect io — carries out the chosen command
#! @taint bridge — extract<Decision> turns the tainted input into a trusted command
grant handle

type Reason = Fraud | NotReceived | Duplicate | Unauthorized
type Decision = Accept | Contest(Reason) | Escalate

let dispute = fetch<web>  # UNTRUSTED a chargeback dispute — tainted
quarantined { let d = extract<Decision>(dispute) }  # only a fixed Decision (payload too) crosses
privileged { handle(d) }  # act on the trusted command only
