import { handler } from './main-function';
import { expect, jest, describe, it, beforeEach } from '@jest/globals';
import { HookEventType, PluginContext, PluginParameters } from '../types';

jest.mock('../utils', () => ({
  post: jest.fn(),
  getText: jest.fn(),
}));

import { post, getText } from '../utils';

const ZSCALER_WEBHOOK_URL_FOR_TEST =
  'https://api.dev1.zseclipse.net/v1/portkey/validate';

describe('Zscaler AI Guard Plugin Handler', () => {
  let mockPost: jest.Mock<
    (...args: any[]) => Promise<{
      action: 'allow' | 'deny';
      validation: boolean;
      message?: string;
    }>
  >;
  let mockGetText: jest.Mock<(...args: any[]) => string | null>;

  const mockCredentials = {
    zscalerApiKey: 'test-api-key-123',
  };

  const mockPluginParameters: PluginParameters<{
    zscalerAiGuardCheck: typeof mockCredentials;
  }> = {
    credentials: {
      zscalerAiGuardCheck: mockCredentials,
    },
  };

  const mockPluginContext: PluginContext = {
    request: {
      id: 'req-123',
    },
  };

  beforeEach(() => {
    mockPost = post as typeof mockPost;
    mockGetText = getText as typeof mockGetText;
    mockPost.mockClear();
    mockGetText.mockClear();

    mockGetText.mockReturnValue('This is a test prompt.');
    mockPost.mockResolvedValue({
      action: 'allow',
      validation: true,
      message: 'Scan completed. No violations found.',
    });
  });

  it('should return a successful verdict for beforeRequestHook when Zscaler allows', async () => {
    mockPost.mockResolvedValueOnce({
      action: 'allow',
      validation: true,
      message: 'Scan completed. No violations found.',
    });
    const result = await handler(
      mockPluginContext,
      mockPluginParameters,
      'beforeRequestHook'
    );

    expect(result.verdict).toBe(true);
    expect(result.error).toBeNull();
    expect(result.data).toEqual({
      message: 'Scan completed. No violations found.',
    });
    expect(mockGetText).toHaveBeenCalledWith(
      mockPluginContext,
      'beforeRequestHook'
    );
    expect(mockPost).toHaveBeenCalledWith(
      ZSCALER_WEBHOOK_URL_FOR_TEST,
      expect.objectContaining({
        input: 'This is a test prompt.',
        type: 'input',
      }),
      expect.objectContaining({
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${mockCredentials.zscalerApiKey}`,
        },
      }),
      expect.any(Number)
    );
  });

  it('should return a successful verdict for afterRequestHook when Zscaler allows', async () => {
    mockPost.mockResolvedValueOnce({
      action: 'allow',
      validation: true,
      message: 'Scan completed. No violations found.',
    });
    mockGetText.mockReturnValue('This is a test response.');
    const result = await handler(
      mockPluginContext,
      mockPluginParameters,
      'afterRequestHook'
    );

    expect(result.verdict).toBe(true);
    expect(result.error).toBeNull();
    expect(result.data).toEqual({
      message: 'Scan completed. No violations found.',
    });
    expect(mockGetText).toHaveBeenCalledWith(
      mockPluginContext,
      'afterRequestHook'
    );
    expect(mockPost).toHaveBeenCalledWith(
      ZSCALER_WEBHOOK_URL_FOR_TEST,
      expect.objectContaining({
        input: 'This is a test response.',
        type: 'output',
      }),
      expect.any(Object),
      expect.any(Number)
    );
  });

  it('should return a failed verdict when Zscaler denies the content', async () => {
    mockPost.mockResolvedValueOnce({
      action: 'deny',
      validation: false,
      message: 'Sensitive data detected.',
    });

    const result = await handler(
      mockPluginContext,
      mockPluginParameters,
      'beforeRequestHook'
    );

    expect(result.verdict).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
    expect(result.error?.message).toContain('Sensitive data detected.');
    expect(result.data).toEqual({ message: 'Sensitive data detected.' });
  });

  it('should return a failed verdict if zscalerApiKey is missing', async () => {
    const paramsWithoutKey = {
      credentials: {
        zscalerAiGuardCheck: { ...mockCredentials, zscalerApiKey: '' },
      },
    };

    const result = await handler(
      mockPluginContext,
      paramsWithoutKey as any,
      'beforeRequestHook'
    );

    expect(result.verdict).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
    expect(result.error?.message).toContain(
      'Zscaler AI Guard API Key must be configured.'
    );
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should return an allowed verdict if no content is found to scan (as per current logic)', async () => {
    mockGetText.mockReturnValue(null);

    const result = await handler(
      mockPluginContext,
      mockPluginParameters,
      'beforeRequestHook'
    );

    expect(result.verdict).toBe(true);
    expect(result.error).toBeInstanceOf(Error);
    expect(result.error?.message).toContain('No content found to scan.');
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('should return a failed verdict if the HTTP call to Zscaler fails', async () => {
    mockPost.mockRejectedValueOnce(new Error('Network error'));

    const result = await handler(
      mockPluginContext,
      mockPluginParameters,
      'beforeRequestHook'
    );

    expect(result.verdict).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
    expect(result.error?.message).toContain(
      'Zscaler AI Guard integration error: Network error'
    );
    expect(result.data).toEqual({ originalError: 'Network error' });
  });

  it('should handle an unknown error during HTTP call gracefully', async () => {
    mockPost.mockRejectedValueOnce('Unknown rejection');

    const result = await handler(
      mockPluginContext,
      mockPluginParameters,
      'beforeRequestHook'
    );

    expect(result.verdict).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
    expect(result.error?.message).toContain(
      'Zscaler AI Guard integration error: Unknown error'
    );
    expect(result.data).toEqual({ originalError: undefined });
  });
});
