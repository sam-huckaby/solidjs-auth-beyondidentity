import {
  redirect,
  useAction,
  useSearchParams,
  useSubmission,
  type RouteSectionProps
} from "@solidjs/router";
import { Show, onMount } from "solid-js";
import { authExchange, passkeyAuth } from "~/lib";

export default function Login(props: RouteSectionProps) {
  const [params, setParams] = useSearchParams();

  if (!params.code || !params.state) {
    console.log("The authentication response was malformed, returning the user to the home page");
    redirect("/");
  }

  // initialize the action that will redeem the authorization code and update the session
  const exchange = useAction(authExchange);

  onMount(async () => {
    exchange(params.code || "", params.state || "");
  });

  return (
    <main onLoad={() => exchange(params.code || "", params.state || "")}>
      <h1>Logging you in...</h1>
    </main>
  );
}
