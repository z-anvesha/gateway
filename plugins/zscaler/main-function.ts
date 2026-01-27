import {
  HookEventType,
  PluginContext,
  PluginHandler,
  PluginParameters,
} from '../types';
import { post, getText } from '../utils';

const ZSCALER_WEBHOOK_URL =
  'https://api.dev1.zseclipse.net/v1/portkey/validate';

interface ZscalerCredentials {
  zscalerApiKey: string;
}

interface ZscalerWebhookRequest {
  input: string;
  metadata: Record<string, any>;
  type: 'input' | 'output';
}

interface ZscalerWebhookResponse {
  action: 'allow' | 'deny';
  validation: boolean;
  message?: string;
}

export const handler: PluginHandler<{
  zscalerAiGuardCheck: ZscalerCredentials;
}> = async (
  context: PluginContext,
  parameters: PluginParameters<{ zscalerAiGuardCheck: ZscalerCredentials }>,
  eventType: HookEventType
) => {
  let error: Error | null = null;
  let verdict: boolean = true;
  let data: Record<string, any> = {};

  const credentials = parameters.credentials?.zscalerAiGuardCheck;

  if (!credentials?.zscalerApiKey) {
    error = new Error('Zscaler AI Guard API Key must be configured.');
    verdict = false;
    return { error, verdict, data };
  }

  const contentToScan = getText(context, eventType);
  if (!contentToScan) {
    error = new Error('No content found to scan.');
    return { error, verdict: true, data };
  }

  const requestType = eventType === 'beforeRequestHook' ? 'input' : 'output';

  const zscalerRequest: ZscalerWebhookRequest = {
    input: contentToScan,
    metadata: {
      portkeyRequestId: context.request?.id || context.response?.id,
    },
    type: requestType,
  };

  try {
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${credentials.zscalerApiKey}`,
    };

    const zscalerResponse: ZscalerWebhookResponse = await post(
      ZSCALER_WEBHOOK_URL, // Use the hardcoded URL here
      zscalerRequest,
      { headers },
      5000
    );

    verdict = zscalerResponse.validation;
    if (zscalerResponse.action === 'deny') {
      error = new Error(
        zscalerResponse.message || 'Zscaler AI Guard blocked the content.'
      );
      data = { message: zscalerResponse.message };
    } else {
      data = { message: zscalerResponse.message };
    }
  } catch (e: any) {
    error = new Error(
      `Zscaler AI Guard integration error: ${e.message || 'Unknown error'}`
    );
    verdict = false;
    data = { originalError: e.message };
  }

  return {
    error,
    verdict,
    data,
  };
};
