import { ApiError, isApiError } from "./api";

/**
 * Error presentation — the single funnel from an unknown thrown value to something a screen can
 * show. Per SEC-002 / the error envelope contract, an {@link ApiError}'s `problem.title` is
 * already user-safe and is rendered verbatim; anything else collapses to a generic line so a raw
 * exception message never reaches the UI.
 */

const GENERIC = "Something went wrong. Please try again.";

export function getErrorMessage(error: unknown): string {
  if (isApiError(error)) return error.problem.title || GENERIC;
  return GENERIC;
}

/** Validation map (field path → messages) from a 422, or an empty object. */
export function fieldErrorsOf(error: unknown): Record<string, string[]> {
  return isApiError(error) ? error.fieldErrors : {};
}

/** First message for one field path, if the error is a 422 mentioning it. */
export function fieldError(error: unknown, field: string): string | undefined {
  return fieldErrorsOf(error)[field]?.[0];
}

/** True when the error carries a retry hint (transport failure or 5xx). */
export function isRetryable(error: unknown): boolean {
  return isApiError(error) ? error.retryable : true;
}

export { ApiError, isApiError };
