import { afterEach, describe, expect, it, vi } from 'vitest';
import { SdkLogger } from './logger';

describe('SdkLogger credential redaction', () => {
    afterEach(() => vi.restoreAllMocks());

    it('redacts sensitive keys and credential-shaped values recursively', () => {
        const output = vi.spyOn(console, 'log').mockImplementation(() => undefined);
        new SdkLogger('test').info('request', {
            authorization: 'Bearer secret-value',
            nested: {
                refreshToken: 'eyJheader.payload.signature',
                safe: 'Bearer another-secret',
            },
        });

        const line = String(output.mock.calls[0]?.[0]);
        expect(line).not.toContain('secret-value');
        expect(line).not.toContain('another-secret');
        expect(line).not.toContain('eyJheader.payload.signature');
        expect(line).toContain('[REDACTED]');
    });
});
