"use client";

/**
 * Data-access hooks — the consistent read/write pattern every screen uses so none of them
 * hand-rolls a fetch effect. `useApiResource` is for GETs (loading/error/data + refetch, with
 * optional polling); `useMutation` is for POST/PATCH/DELETE actions (tracks in-flight + the raw
 * error so forms can pull field-level messages off an {@link ApiError}).
 */

import * as React from "react";

import { getErrorMessage } from "@/lib/errors";

interface ResourceState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

interface UseApiResourceOptions {
  /** Skip fetching until true. Default true. */
  enabled?: boolean;
  /** Poll every N ms while mounted and enabled. Default: no polling. */
  refetchInterval?: number;
}

export interface UseApiResourceResult<T> extends ResourceState<T> {
  refetch: () => void;
  /** Set locally without a round-trip (e.g. after a mutation returns the new entity). */
  setData: (data: T) => void;
}

export function useApiResource<T>(
  fetcher: () => Promise<T>,
  deps: React.DependencyList,
  options: UseApiResourceOptions = {},
): UseApiResourceResult<T> {
  const { enabled = true, refetchInterval } = options;

  const [state, setState] = React.useState<ResourceState<T>>({
    data: null,
    error: null,
    loading: enabled,
  });

  // Keep the latest fetcher without making it a dependency (callers pass it inline).
  const fetcherRef = React.useRef(fetcher);
  fetcherRef.current = fetcher;

  // Guards against out-of-order responses and post-unmount setState.
  const reqIdRef = React.useRef(0);
  const mountedRef = React.useRef(true);
  React.useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = React.useCallback(async () => {
    const reqId = ++reqIdRef.current;
    setState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const data = await fetcherRef.current();
      if (mountedRef.current && reqId === reqIdRef.current) {
        setState({ data, error: null, loading: false });
      }
    } catch (error) {
      if (mountedRef.current && reqId === reqIdRef.current) {
        setState((prev) => ({ ...prev, error: getErrorMessage(error), loading: false }));
      }
    }
  }, []);

  React.useEffect(() => {
    if (!enabled) {
      setState({ data: null, error: null, loading: false });
      return;
    }
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps]);

  React.useEffect(() => {
    if (!enabled || !refetchInterval) return;
    const timer = setInterval(() => void load(), refetchInterval);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, refetchInterval, ...deps]);

  const setData = React.useCallback((data: T) => {
    setState((prev) => ({ ...prev, data }));
  }, []);

  return { ...state, refetch: () => void load(), setData };
}

export interface UseMutationResult<A extends unknown[], R> {
  /** Run the action. Resolves to the result, or `undefined` if it failed (error is captured). */
  run: (...args: A) => Promise<R | undefined>;
  loading: boolean;
  /** Raw thrown value — inspect for `ApiError.fieldErrors` in forms. */
  error: unknown;
  errorMessage: string | null;
  reset: () => void;
}

export function useMutation<A extends unknown[], R>(
  fn: (...args: A) => Promise<R>,
  options: { onSuccess?: (result: R) => void; onError?: (error: unknown) => void } = {},
): UseMutationResult<A, R> {
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<unknown>(null);

  const fnRef = React.useRef(fn);
  fnRef.current = fn;
  const optsRef = React.useRef(options);
  optsRef.current = options;

  const mountedRef = React.useRef(true);
  React.useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const run = React.useCallback(async (...args: A): Promise<R | undefined> => {
    setLoading(true);
    setError(null);
    try {
      const result = await fnRef.current(...args);
      optsRef.current.onSuccess?.(result);
      return result;
    } catch (err) {
      if (mountedRef.current) setError(err);
      optsRef.current.onError?.(err);
      return undefined;
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, []);

  return {
    run,
    loading,
    error,
    errorMessage: error ? getErrorMessage(error) : null,
    reset: () => setError(null),
  };
}
