exports.version = 1.0;
exports.apiRequired = 1;
exports.description = "Whitelist plugin to restrict access based on IP addresses";
exports.repo = "illskillz24-cho3/whitelist-plugin";

exports.config = {
    whitelist: {
        type: 'array',
        label: 'Whitelisted IP Addresses',
        helperText: 'Enter allowed IP addresses. If your IP is not listed, you will be blocked from accessing the server.',
        fields: {
            ip: {
                type: 'string',
                label: 'IP Address',
                defaultValue: '127.0.0.1',
                helperText: 'Example: 192.168.1.100'
            }
        }
    }
};

exports.init = api => {
    return {
        middleware(ctx) {
            // Retrieve the whitelist from the config (an array of objects with an "ip" property)
            const whitelist = (api.getConfig('whitelist') || []).map(item => item.ip.trim());
            
            // Only enforce if there is at least one IP defined
            if (whitelist.length > 0) {
                if (!whitelist.includes(ctx.ip)) {
                    ctx.status = 403;
                    ctx.body = 'Forbidden: Your IP is not whitelisted.';
                    return ctx.stop?.() || true;
                }
            }
            // If the whitelist is empty, all requests are allowed.
        }
    }
};
