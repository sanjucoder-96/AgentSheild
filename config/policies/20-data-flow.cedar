// Where values came from and what they carry, across the whole session.

@id("block-credential-in-arguments")
@reason("Credentials never belong in tool arguments; the gateway injects them itself.")
forbid (principal, action, resource)
when { context.contains_secret };

@id("block-injected-recipient-with-private-data")
@reason("A destination copied from untrusted content may not receive private data.")
forbid (principal, action, resource)
when { context.destination_from_untrusted && context.carries_private_data };

@id("lethal-trifecta-needs-approval")
@approval("required")
@reason("Session read untrusted content and private data, and this call sends private data out.")
permit (principal, action, resource)
when {
  principal.allowed_tools.contains(resource.name) &&
  resource.sends_external && context.session_tainted && context.carries_private_data
};
