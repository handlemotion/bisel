import { expect, test } from "@playwright/test";
import { sql } from "../support/server";

// A new person makes an account with a passkey, signs out and signs back in with it: the browser half of Better Auth's
// passkey ceremony against the real Worker. (Everything the dashboard does after sign-in is covered by tests/accounts.test.ts.)
test("sign up with a passkey, sign out, sign in again", async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await page.goto("/");
  await page.getByPlaceholder(/Your name/).fill("Rodrigo");
  await page.getByRole("button", { name: "Create account with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Rodrigo" })).toBeVisible();

  // The account carries a placeholder address, not anything the person typed.
  const users = sql(process.env.BISEL_TEST_STATE!, "SELECT name, email FROM user");
  expect(users).toEqual([
    { name: "Rodrigo", email: expect.stringMatching(/^[0-9a-f]{32}@accounts\.bisel\.invalid$/) },
  ]);

  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Rodrigo" })).toBeVisible();
});
