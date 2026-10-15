export interface KnowledgeCollection {
  id: string;
  name: string;
  description: string | null;
  retrieval_provider: "internal" | "dify";
  retrieval_policy: Record<string, unknown>;
  is_enabled: boolean;
  revision: number;
}

export interface KnowledgeSource {
  id: string;
  collection_id: string;
  filename: string;
  size_bytes: number;
  status: "storing" | "stored" | "extracting" | "chunking" | "embedding" | "ready" | "failed" | "deleted";
  error_code: string | null;
  indexed_chunks: number;
  total_chunks: number;
  index_attempts: number;
  embedding_profile: string | null;
}

export interface KnowledgeHit {
  chunk_id: string;
  source_id: string;
  text: string;
  score: number;
  citation: {
    collection_id: string;
    filename: string;
    page: number | null;
    section: string | null;
    content_hash: string;
    provider: "internal" | "dify";
  };
}

export interface CollectionCreateInput {
  name: string;
  description?: string;
  retrieval_provider: "internal" | "dify";
  retrieval_policy: { embedding: { provider: "openai" | "google"; model: string } };
}

export const MAX_KNOWLEDGE_BYTES = 20 * 1024 * 1024;
export const TERMINAL_SOURCE_STATES = new Set(["ready", "failed", "deleted"]);
export function validateKnowledgeFile(file: Pick<File, "name" | "size">): string | null {
  if (!/\.(pdf|txt|md|json|sarif)$/i.test(file.name)) return "Choose a PDF, Markdown, text, JSON, SARIF, or JSON SBOM file.";
  if (file.size === 0) return "The document is empty.";
  if (file.size > MAX_KNOWLEDGE_BYTES) return "Documents must be 20 MB or smaller.";
  return null;
}

export function knowledgeFileType(name: string): string {
  return /\.pdf$/i.test(name) ? "application/pdf" : /\.md$/i.test(name) ? "text/markdown" : /\.(json|sarif)$/i.test(name) ? "application/json" : "text/plain";
}

export function sourceStatus(source: KnowledgeSource): string {
  if (source.status === "stored") return source.error_code ? "Waiting to retry" : "Queued for indexing";
  if (source.status === "embedding") return `Indexing ${source.indexed_chunks} of ${source.total_chunks} passages`;
  if (source.status === "failed") return (source.error_code ?? "Indexing failed").replaceAll("_", " ");
  return source.status.charAt(0).toUpperCase() + source.status.slice(1);
}
