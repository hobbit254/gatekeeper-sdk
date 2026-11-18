// The example's sign-in and API calls (FR-T9, ADR-0130), kept apart from the
// page so the live test can drive them. Register a public client with
// redirect URI <origin>/callback and the API's identifier as an API audience.
import { createBrowserClient } from "@hobbit254/gatekeeper-sdk/browser";

export interface Config {
  issuer: string;
  clientId: string;
  /** Where the browser comes back after signing in: <origin>/callback. */
  redirectUri: string;
  /** The API to call with the user's access token. */
  apiUrl: string;
  /** Overrides for tests; a page uses the browser's own. */
  navigate?: (url: string) => void;
  fetch?: typeof fetch;
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">;
}

export function createApp(c: Config) {
  const doFetch = c.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const auth = createBrowserClient({ issuer: c.issuer, clientId: c.clientId, redirectUri: c.redirectUri,
    scope: "openid profile offline_access", navigate: c.navigate, fetch: c.fetch, storage: c.storage });
  return {
    /** Sends the browser to Gatekeeper's sign-in page. */
    signIn: () => auth.loginWithRedirect(),
    /** On /callback: checks the response, exchanges the code and returns the user's ID token claims. */
    finishSignIn: (url?: string) => auth.handleRedirectCallback(url),
    /** Calls the API with the user's access token. */
    async callApi(path: string): Promise<{ status: number; body: string }> {
      const res = await doFetch(c.apiUrl + path, { headers: { Authorization: `Bearer ${await auth.getAccessToken()}` } });
      return { status: res.status, body: await res.text() };
    },
    signOut: (returnTo: string) => auth.logout({ returnTo }),
  };
}
