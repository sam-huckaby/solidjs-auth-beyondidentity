import { action, cache, redirect } from "@solidjs/router";
import { db } from "./db";
import { getSession, login, logout as logoutSession, register, validatePassword, validateUsername } from "./server";
import { randomBytes, createHash } from "crypto";

export const getUser = cache(async () => {
  "use server";
  try {
    const session = await getSession();
    const userId = session.data.userId;
    if (userId === undefined) throw new Error("User not found");
    const user = await db.user.findUnique({ where: { id: userId } });
    if (!user) throw new Error("User not found");
    return { id: user.id, username: user.username };
  } catch {
    await logoutSession();
    throw redirect("/login");
  }
}, "user");

// This is the old password way
/*
export const loginOrRegister = action(async (formData: FormData) => {
  "use server";
  const username = String(formData.get("username"));
  const password = String(formData.get("password"));
  const loginType = String(formData.get("loginType"));
  let error = validateUsername(username) || validatePassword(password);
  if (error) return new Error(error);

  try {
    const user = await (loginType !== "login"
      ? register(username, password)
      : login(username, password));
    const session = await getSession();
    await session.update(d => (d.userId = user!.id));
  } catch (err) {
    return err as Error;
  }
  return redirect("/");
});
*/

// This server action will handle building the Auth URL and passing the UA on to it
// UA => User Agent a.k.a. a user's browser
export const passkeyAuth = action(async () => {
  "use server";

  // Create one-time use value to verify you spoke to the same person through the whole request (stop CSRF)
  // We call this a "nonce" in the US, but that means something wildly different in the UK
  const randomState = randomBytes(32).toString('base64url');
  // This is another one-time use value that will become the "answer" to our PKCE "question" (challenge)
  const codeVerifier = randomBytes(32).toString('base64url');
  // This is an encrypted version of our PKCE "answer" that will be used to prove authenticity
  const codeChallenge = createHash('sha256')
    .update(codeVerifier)
    .digest()
    .toString('base64url');

  // This is the URI in OUR app that Beyond Identity will redirect the UA to after authentication/registration
  const redirectURI = encodeURI(process.env.APP_REDIRECT_URI || "");

  // This modified auth url includes PKCE method/challenge - remove those if not using PKCE - but you should use PKCE
  const authURI = `https://auth-us.beyondidentity.com/v1/tenants/${process.env.BI_TENANT_ID}/realms/${process.env.BI_REALM_ID}/applications/${process.env.BI_APPLICATION_ID}/authorize?response_type=code&client_id=${process.env.BI_CLIENT_ID}&redirect_uri=${redirectURI}&scope=openid&state=${randomState}&code_challenge_method=S256&code_challenge=${codeChallenge}`;

  // Update the session to track the CSRF state value and our PKCE "answer"
  try {
    const session = await getSession();
    await session.update(sess => {
      sess.state_value = randomState;
      sess.code_verifier = codeVerifier;
    });
  } catch (err) {
    return err as Error;
  }

  // Send the UA on to Beyond Identity
  return redirect(authURI);
});

// This server action will handle the post-authentication handshake and 
// initializing the auth details in the session
export const authExchange = action(async (code: string, state: string) => {
  "use server";

  try {
    const session = await getSession();

    // If there is no state data in the session, this is a new session and needs to go back to the home page
    if (session.data.state_value !== state) {
      console.log("Session is not in an auth-ready state");
      redirect("/");
    }

    // This is that PKCE "answer" again, if you aren't using PKCE you can get rid of it
    // You should really use PKCE though, because why not be secure?
    const codeVerifier = session.data.code_verifier;

    // Grab these values from our Beyond Identity Application
    const clientID = process.env.BI_CLIENT_ID || "";
    const clientSecret = process.env.BI_CLIENT_SECRET || "";
    const redirectURI = encodeURI(process.env.APP_REDIRECT_URI || "");


    const tokenResp = await fetch(
      `https://auth-us.beyondidentity.com/v1/tenants/${process.env.BI_TENANT_ID}/realms/${process.env.BI_REALM_ID}/applications/${process.env.BI_APPLICATION_ID}/token`,
      {
        method: "POST",
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + btoa(`${clientID}:${clientSecret}`)
        },
        body: `grant_type=authorization_code&code=${code}&code_verifier=${codeVerifier}&redirect_uri=${redirectURI}`
      }
    );

    // Read the interesting things that were returned to us
    // access_token is the Bearer token you use to authenticate with an upstream SP (service provider)
    // token_type is the type of token that access_token is
    // expires_in is exactly what it sounds like - time before this token expires
    // scope is a list of custom scopes that your token has
    // id_token is a JWT that includes all of the authenticating user's information (that Beyond Identity has)
    const values = await tokenResp.json();
    const {
      access_token, // EX: A JWT
      token_type, // EX: 'Bearer'
      expires_in, // EX: 86400
      scope, // EX: ''
      id_token, // EX: A JWT
    } = values;

    console.log(values);

  } catch (err) {
    return err as Error;
  }

  redirect("/");
});

export const logout = action(async () => {
  "use server";
  await logoutSession();
  return redirect("/login");
});
