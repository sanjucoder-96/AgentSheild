// Where data may go. Every URL host and email domain is checked after decoding.

@id("block-unapproved-destination")
@reason("Data may only be sent to allowlisted email domains and web hosts.")
forbid (principal, action, resource)
when { context.has_destination && !context.all_destinations_allowlisted };

@id("block-internal-network")
@reason("Calls may not reach private network or cloud metadata addresses (SSRF).")
forbid (principal, action, resource)
when { context.private_destination || context.metadata_destination };

@id("block-lookalike-domain")
@reason("The destination imitates an approved domain using lookalike characters.")
forbid (principal, action, resource)
when { context.lookalike_destination };

@id("block-unresolvable-destination")
@reason("An approved host did not resolve, so its address cannot be checked.")
forbid (principal, action, resource)
when { context.destination_unresolvable };
