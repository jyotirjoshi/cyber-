import { redirect } from "next/navigation";

export default function RootIndexPage(): never {
  redirect("/dashboard");
}
