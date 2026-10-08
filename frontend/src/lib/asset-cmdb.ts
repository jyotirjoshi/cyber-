import type { CmdbImportOut } from "./types";

export function canApplyCmdbPreview(
  selectedFile: File | null,
  previewedFile: File | null,
  preview: CmdbImportOut | null,
): boolean {
  return selectedFile !== null && selectedFile === previewedFile &&
    preview?.dry_run === true && preview.matched > 0;
}
