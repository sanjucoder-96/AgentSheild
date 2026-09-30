// What may run. These apply even to tools an agent is allowed to use.

@id("block-path-escape")
@reason("File paths must stay inside the workspace.")
forbid (principal, action, resource)
when { context.path_escape };

@id("block-destructive-command")
@reason("Commands that destroy data or systems are never run.")
forbid (principal, action, resource)
when { context.command_destructive };

@id("block-command-injection")
@reason("Shell metacharacters or option smuggling detected in a command.")
forbid (principal, action, resource)
when { context.command_injection };

@id("block-sql-write")
@reason("The customer database is read-only for agents.")
forbid (principal, action, resource)
when { context.sql_write };
