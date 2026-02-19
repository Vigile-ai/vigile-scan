import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VigileApiClient } from '../../src/api/client.js';

describe('VigileApiClient', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('strips trailing slashes from baseUrl', () => {
      const client = new VigileApiClient('https://api.example.com///');
      expect(client['baseUrl']).toBe('https://api.example.com');
    });

    it('defaults to api.vigile.dev when no URL provided', () => {
      const originalEnv = process.env.VIGILE_API_URL;
      delete process.env.VIGILE_API_URL;
      const client = new VigileApiClient();
      expect(client['baseUrl']).toBe('https://api.vigile.dev');
      process.env.VIGILE_API_URL = originalEnv;
    });

    it('uses env var VIGILE_API_URL if set', () => {
      const originalEnv = process.env.VIGILE_API_URL;
      process.env.VIGILE_API_URL = 'https://custom.api.com';
      const client = new VigileApiClient();
      expect(client['baseUrl']).toBe('https://custom.api.com');
      process.env.VIGILE_API_URL = originalEnv;
    });
  });

  describe('isAuthenticated', () => {
    it('returns true when token is set', () => {
      const client = new VigileApiClient('https://api.test.com', 'valid-token');
      expect(client.isAuthenticated).toBe(true);
    });

    it('returns false when token is null', () => {
      const client = new VigileApiClient('https://api.test.com', null);
      expect(client.isAuthenticated).toBe(false);
    });

    it('returns false when token is empty string', () => {
      const client = new VigileApiClient('https://api.test.com', '');
      expect(client.isAuthenticated).toBe(false);
    });
  });

  describe('getMe', () => {
    it('returns ok:true with user data on success', async () => {
      const mockUser = { id: 1, email: 'test@test.com', name: 'Test', tier: 'pro' };
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(JSON.stringify(mockUser), { status: 200 })
      );

      const client = new VigileApiClient('https://api.test.com', 'token');
      const result = await client.getMe();

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.data.email).toBe('test@test.com');
        expect(result.data.tier).toBe('pro');
      }
    });

    it('returns ok:false on 401', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(JSON.stringify({ detail: 'Authentication required' }), { status: 401 })
      );

      const client = new VigileApiClient('https://api.test.com', 'bad-token');
      const result = await client.getMe();

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.status).toBe(401);
        expect(result.error).toBe('Authentication required');
      }
    });

    it('returns ok:false on network error', async () => {
      vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const client = new VigileApiClient('https://api.test.com', 'token');
      const result = await client.getMe();

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.status).toBe(0);
        expect(result.error).toBe('ECONNREFUSED');
      }
    });
  });

  describe('submitMCPScan', () => {
    it('sends POST to /api/v1/scan/ with correct payload', async () => {
      const mockResponse = {
        id: 1,
        server_name: 'test-server',
        trust_score: 85,
        trust_level: 'trusted',
        score_breakdown: {},
        findings: [],
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        scanner_version: '0.2.0',
        scanned_at: new Date().toISOString(),
      };

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(JSON.stringify(mockResponse), { status: 200 })
      );

      const client = new VigileApiClient('https://api.test.com', 'token');
      const result = await client.submitMCPScan({ server_name: 'test-server' });

      expect(result.ok).toBe(true);
      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.test.com/api/v1/scan/',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ server_name: 'test-server' }),
        })
      );
    });
  });

  describe('submitSkillScan', () => {
    it('sends POST to /api/v1/scan/skill', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 1 }), { status: 200 })
      );

      const client = new VigileApiClient('https://api.test.com', 'token');
      await client.submitSkillScan({
        skill_name: 'test-skill',
        content: '# Test skill content',
      });

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.test.com/api/v1/scan/skill',
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('Sentinel methods', () => {
    it('createSentinelSession sends correct payload', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            session_id: 1,
            server_name: 'test',
            max_duration_seconds: 300,
            status: 'active',
            created_at: new Date().toISOString(),
          }),
          { status: 200 }
        )
      );

      const client = new VigileApiClient('https://api.test.com', 'token');
      await client.createSentinelSession('test-server', 300);

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.test.com/api/v1/sentinel/sessions',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            server_name: 'test-server',
            duration_seconds: 300,
            client: 'cli',
          }),
        })
      );
    });

    it('submitSentinelEvents sends to correct path', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(
          JSON.stringify({ status: 'ok', events_received: 3, total_events: 10 }),
          { status: 200 }
        )
      );

      const client = new VigileApiClient('https://api.test.com', 'token');
      await client.submitSentinelEvents(42, []);

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.test.com/api/v1/sentinel/sessions/42/events',
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('analyzeSentinelSession sends to correct path', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 1 }), { status: 200 })
      );

      const client = new VigileApiClient('https://api.test.com', 'token');
      await client.analyzeSentinelSession(42);

      expect(fetchSpy).toHaveBeenCalledWith(
        'https://api.test.com/api/v1/sentinel/sessions/42/analyze',
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('request headers', () => {
    it('includes Authorization header when authenticated', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );

      const client = new VigileApiClient('https://api.test.com', 'my-token');
      await client.getMe();

      const headers = fetchSpy.mock.calls[0][1]?.headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer my-token');
    });

    it('includes User-Agent header', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response(JSON.stringify({}), { status: 200 })
      );

      const client = new VigileApiClient('https://api.test.com', 'token');
      await client.getMe();

      const headers = fetchSpy.mock.calls[0][1]?.headers as Record<string, string>;
      expect(headers['User-Agent']).toMatch(/^vigile-cli\//);
    });
  });
});
