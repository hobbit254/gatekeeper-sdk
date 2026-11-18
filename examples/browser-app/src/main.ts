import { createApp } from "./app";

const app = createApp({
  issuer: import.meta.env.VITE_GK_ISSUER,
  clientId: import.meta.env.VITE_GK_CLIENT_ID,
  redirectUri: `${location.origin}/callback`,
  apiUrl: import.meta.env.VITE_GK_API_URL,
});

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const show = (signedIn: boolean) => {
  $("sign-in").hidden = signedIn;
  for (const id of ["me", "reports", "sign-out"]) $(id).hidden = !signedIn;
};
const call = (path: string) => async () => {
  const r = await app.callApi(path);
  $("output").textContent = `${r.status}\n${r.body}`; // 403 on /api/reports until a role grants report:read
};

$("sign-in").onclick = () => app.signIn();
$("me").onclick = call("/api/me");
$("reports").onclick = call("/api/reports");
$("sign-out").onclick = () => app.signOut(location.origin);

if (location.pathname === "/callback") {
  app.finishSignIn().then((user) => {
    history.replaceState(null, "", "/");
    $("status").textContent = `Signed in as ${String(user.name ?? user.email ?? user.sub)}.`;
    show(true);
  }, (e: Error) => { $("status").textContent = `Sign-in failed: ${e.message}`; });
}
// Tokens live in memory only, so a reload signs out of the app (not of Gatekeeper: Sign in is then one click).
