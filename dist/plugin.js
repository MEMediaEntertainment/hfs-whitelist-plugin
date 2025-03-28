exports.version = 1.32
exports.apiRequired = 8.891
exports.description = "Whitelist plugin with support for single IPs, CIDR ranges, and wildcard notation (e.g., 98.243.*.*). Localhost (127.0.0.1 and ::1) are always allowed."
exports.repo = "MEMediaEntertainment/hfs-whitelist-plugin"
exports.preview = ["https://camo.githubusercontent.com/49e8d9d754a709f5a9263f14fdf7e25ddf8e75b06629736d6b33cb30cf5af01f/68747470733a2f2f692e6962622e636f2f7477647a775154632f73637265656e73686f742e706e67"]

exports.config = {
    whitelist: {
        type: "array",
        label: "Whitelisted IP Addresses",
        helperText: "Enter allowed IP addresses. You can use a single IP (e.g., 192.168.1.100), a CIDR range (e.g., 192.168.1.0/24), or a wildcard format (e.g., 98.243.*.*). Localhost (127.0.0.1 and ::1) are always allowed.",
        fields: {
            ip: {
                type: "string",
                label: "IP Address or Range",
                defaultValue: "127.0.0.1",
                helperText: "Examples: 192.168.1.100, 192.168.1.0/24, or 98.243.*.*"
            }
        }
    }
};

// Convert an IPv4 address to a numeric value
function ipToLong(ip) {
    return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

// Check if an IPv4 address falls within a CIDR range (e.g., 192.168.1.0/24)
function isIpInCidr(ip, cidr) {
    const [range, bits] = cidr.split("/");
    const ipLong = ipToLong(ip);
    const rangeLong = ipToLong(range);
    const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
    return (ipLong & mask) === (rangeLong & mask);
}

// Check if an IP matches a wildcard pattern (e.g., 98.243.*.*)
function isIpWildcardMatch(ip, pattern) {
    // Convert wildcard pattern to a regular expression
    const regexStr = "^" + pattern.split(".").map(part => {
        return part === "*" ? "[0-9]{1,3}" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }).join("\\.") + "$";
    const re = new RegExp(regexStr);
    return re.test(ip);
}

exports.init = api => {
    return {
        middleware(ctx) {
            // Automatically allow local connections (IPv4 and IPv6)
            if (ctx.ip === "127.0.0.1" || ctx.ip === "::1") {
                return;
            }
            
            // Retrieve and trim whitelist entries
            const whitelist = (api.getConfig("whitelist") || []).map(item => item.ip.trim());
            let allowed = false;
            
            for (const entry of whitelist) {
                if (entry.includes("/")) {
                    // CIDR notation
                    if (isIpInCidr(ctx.ip, entry)) {
                        allowed = true;
                        break;
                    }
                } else if (entry.includes("*")) {
                    // Wildcard pattern
                    if (isIpWildcardMatch(ctx.ip, entry)) {
                        allowed = true;
                        break;
                    }
                } else {
                    // Exact IP match
                    if (entry === ctx.ip) {
                        allowed = true;
                        break;
                    }
                }
            }
            
            if (whitelist.length > 0 && !allowed) {
                ctx.status = 403;
                ctx.body = "Forbidden: Your IP is not whitelisted.";
                return ctx.stop?.() || true;
            }
        }
    };
};
