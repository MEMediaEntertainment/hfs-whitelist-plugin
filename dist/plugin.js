exports.version = 1.3;
exports.apiRequired = 1;
exports.description = "Whitelist plugin with support for single IPs, CIDR ranges, and wildcard notation (e.g., 98.243.*.*). Localhost is always allowed.";
exports.repo = "illskillz24-cgo3/whitelist-plugin";

exports.config = {
    whitelist: {
        type: 'array',
        label: 'Whitelisted IP Addresses',
        helperText: 'Enter allowed IP addresses. You can use a single IP (e.g., 192.168.1.100), a CIDR range (e.g., 192.168.1.0/24), or a wildcard format (e.g., 98.243.*.*). Localhost (127.0.0.1 and ::1) are always allowed.',
        fields: {
            ip: {
                type: 'string',
                label: 'IP Address or Range',
                defaultValue: '127.0.0.1',
                helperText: 'Examples: 192.168.1.100, 192.168.1.0/24, or 98.243.*.*'
            }
        }
    }
};

// Convert an IPv4 address to a numeric value
function ipToLong(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

// Check if an IPv4 address falls within a CIDR range (e.g., 192.168.1.0/24)
function isIpInCidr(ip, cidr) {
    const [range, bits] = cidr.split('/');
    const ipLong = ipToLong(ip);
    const rangeLong = ipToLong(range);
    const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
    return (ipLong & mask) === (rangeLong & mask);
}

// Check if an IP matches a wildcard pattern (e.g., 98.243.*.*)
function isIpWildcardMatch(ip, pattern) {
    // Convert wildcard pattern to a regular expression
    const regexStr = '^' + pattern.split('.').map(part => {
        if (part === '*') return '[0-9]{1,3}';
        return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }).join('\\.') + '$';
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
            const whitelist = (api.getConfig('whitelist') || []).map(item => item.ip.trim());
            let allowed = false;
            for (const entry of whitelist) {
                if (entry.includes('/')) {
                    // Check for CIDR notation
                    if (isIpInCidr(ctx.ip, entry)) {
                        allowed = true;
                        break;
                    }
                } else if (entry.includes('*')) {
                    // Check for wildcard patterns
                    if (isIpWildcardMatch(ctx.ip, entry)) {
                        allowed = true;
                        break;
                    }
                } else {
                    // Check for an exact IP match
                    if (entry === ctx.ip) {
                        allowed = true;
                        break;
                    }
                }
            }
            
            if (whitelist.length > 0 && !allowed) {
                ctx.status = 403;
                ctx.body = 'Forbidden: Your IP is not whitelisted.';
                return ctx.stop?.() || true;
            }
        }
    };
};
