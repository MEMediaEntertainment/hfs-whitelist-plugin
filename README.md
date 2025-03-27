# Whitelist Plugin For HFS
This plugin defines a configuration option—an array of allowed IP addresses—and adds a middleware that checks each incoming request’s IP against the whitelist. If the client's IP isn’t found in the list (when the list is not empty), the request is halted with a 403 Forbidden response.
