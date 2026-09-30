// Who may call what. Nothing is allowed unless a permit below matches:
// Cedar denies by default, and any forbid in the other files overrides these permits.

@id("agent-tool-allowlist")
@reason("Each agent may only call the tools listed for it in the gateway config.")
permit (principal, action, resource)
when { principal.allowed_tools.contains(resource.name) };

@id("destructive-needs-approval")
@approval("required")
@reason("Destructive tools (delete, shell) wait for a human to approve.")
permit (principal, action, resource)
when { principal.allowed_tools.contains(resource.name) && resource.destructive };
