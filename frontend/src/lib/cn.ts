import clsx, { type ClassValue } from "clsx";

/** Compose class names. The single sanctioned className helper for the app. */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
