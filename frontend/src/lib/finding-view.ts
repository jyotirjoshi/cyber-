export type FindingView = "assessment" | "external" | "all" | "canonical";

export function findingViewFromSearch(search: string): FindingView {
  const view = new URLSearchParams(search).get("view");
  return view === "external" || view === "all" || view === "assessment" ? view : "canonical";
}
