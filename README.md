# whitelist-plugin
How It Works:
1. Localhost Bypass:
	The middleware immediately allows connections from "127.0.0.1" and "::1".

2. Whitelist Verification:
	For every other request, the plugin retrieves the whitelist entries and checks each one:

	 A. CIDR Ranges: Uses the isIpInCidr function.

	 B. Wildcard Patterns: Converts patterns like "98.243.*.*" into a regular expression and tests the client's IP.

	 C. Exact Matches: Simply compares the client's IP with the entry.

If none of the whitelist entries match and at least one entry is defined, the request is blocked with a 403 status.

This implementation lets you mix and match IP formats, ensuring flexibility in how you configure your whitelist.

<img src="https://i.ibb.co/twdzwQTc/screenshot.png" alt="screenshot" border="0">
