import {
  HookEventType,
  PluginContext,
  PluginHandler,
  PluginParameters,
} from '../types';
import { post, getText } from '../utils';

const ZSCALER_EXECUTE_POLICY_URL =
  'https://api.zseclipse.net/v1/detection/execute-policy';

interface ZscalerCredentials {
  zscalerApiKey: string;
}

interface ZscalerPluginParameters {
  policyId: string;
}

interface ZscalerExecutePolicyRequest {
  policyId: string;
  direction: 'IN' | 'OUT';
  content: any;
}

interface ZscalerExecutePolicyResponse {
  action: 'ALLOW' | 'BLOCK';
  detectorResponses?: Record<string, any>;
}

export const handler: PluginHandler<ZscalerCredentials> = async (
  context: PluginContext,
  parameters: PluginParameters<ZscalerCredentials>,
  eventType: HookEventType
) => {
  let error: Error | null = null;
  let verdict: boolean = true;
  let data: Record<string, any> = {};

  const credentials = parameters.credentials as ZscalerCredentials | undefined;
  const pluginParams = parameters.parameters as ZscalerPluginParameters;

  if (!credentials?.zscalerApiKey) {
    error = new Error('Zscaler AI Guard API Key must be configured.');
    verdict = false;
    return { error, verdict, data };
  }
  if (!pluginParams.policyId) {
    error = new Error('Zscaler AI Guard Policy ID must be configured.');
    verdict = false;
    return { error, verdict, data };
  }

  const contentToScan = getText(context, eventType);
  if (!contentToScan) {
    return {
      error: new Error('No content found to scan.'),
      verdict: true,
      data,
    };
  }

  const direction = eventType === 'beforeRequestHook' ? 'IN' : 'OUT';

  const zscalerRequest: ZscalerExecutePolicyRequest = {
    policyId: pluginParams.policyId,
    direction: direction,
    content: { text: contentToScan },
  };

  try {
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${credentials.zscalerApiKey}`,
    };

    const zscalerResponse: ZscalerExecutePolicyResponse = await post(
      ZSCALER_EXECUTE_POLICY_URL,
      zscalerRequest,
      { headers },
      10000
    );

    if (zscalerResponse.action === 'ALLOW') {
      verdict = true;
    } else {
      verdict = false;
      error = new Error(
        `Zscaler AI Guard blocked the content with action: ${zscalerResponse.action}`
      );
    }

    data = {
      zscalerAction: zscalerResponse.action,
      detectorResponses: zscalerResponse.detectorResponses,
    };
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
