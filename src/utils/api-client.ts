import axios, { AxiosInstance, AxiosError } from 'axios';
import axiosRetry from 'axios-retry';
import type { TrustScopeConfig, ApiResponse } from '../types/index.js';

export class ApiClient {
  private client: AxiosInstance;
  private apiKey: string;

  constructor(config: TrustScopeConfig) {
    this.apiKey = config.apiKey;

    this.client = axios.create({
      baseURL: config.baseUrl || 'https://api.trustscope.ai',
      timeout: config.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`,
        'X-TrustScope-Source': 'mcp-server',
      },
    });

    // Configure retry logic
    axiosRetry(this.client, {
      retries: 3,
      retryDelay: axiosRetry.exponentialDelay,
      retryCondition: (error: AxiosError) => {
        return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
          (error.response?.status === 429) ||
          (error.response?.status === 503);
      },
    });
  }

  async post<TOutput>(
    endpoint: string,
    data: unknown
  ): Promise<ApiResponse<TOutput>> {
    try {
      const response = await this.client.post<TOutput>(endpoint, data);
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return this.handleError(error);
    }
  }

  async get<TOutput>(
    endpoint: string,
    params?: Record<string, unknown>
  ): Promise<ApiResponse<TOutput>> {
    try {
      const response = await this.client.get<TOutput>(endpoint, { params });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return this.handleError(error);
    }
  }

  private handleError<T>(error: unknown): ApiResponse<T> {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<{ error?: string; message?: string }>;

      if (axiosError.response) {
        const status = axiosError.response.status;
        const data = axiosError.response.data;

        if (status === 401) {
          return {
            success: false,
            error: 'Invalid API key',
            code: 'UNAUTHORIZED',
          };
        }

        if (status === 403) {
          return {
            success: false,
            error: 'Feature requires higher tier subscription',
            code: 'TIER_REQUIRED',
          };
        }

        if (status === 429) {
          return {
            success: false,
            error: 'Rate limit exceeded',
            code: 'RATE_LIMITED',
          };
        }

        return {
          success: false,
          error: data?.error || data?.message || `Request failed with status ${status}`,
          code: `HTTP_${status}`,
        };
      }

      if (axiosError.code === 'ECONNREFUSED') {
        return {
          success: false,
          error: 'Unable to connect to TrustScope API',
          code: 'CONNECTION_ERROR',
        };
      }

      if (axiosError.code === 'ETIMEDOUT') {
        return {
          success: false,
          error: 'Request timed out',
          code: 'TIMEOUT',
        };
      }
    }

    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      code: 'UNKNOWN_ERROR',
    };
  }

  getApiKey(): string {
    return this.apiKey;
  }
}

export function createApiClient(config: TrustScopeConfig): ApiClient {
  return new ApiClient(config);
}
