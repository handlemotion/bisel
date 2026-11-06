export interface TypedLogin {
  username: string;
  password: string;
}

const TEXT_TYPES = new Set(["text", "email", "tel"]);

function tokens(input: HTMLInputElement): string[] {
  return (input.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
}

/**
 * The login in the form that was submitted, or null when this is not a sign-in: exactly one filled password field, no new password or
 * one-time code, and a username. Reads this form's own controls and nothing else on the page.
 */
export function loginFrom(form: HTMLFormElement): TypedLogin | null {
  const inputs = Array.from(form.elements).filter(
    (element): element is HTMLInputElement => element.tagName === "INPUT",
  );
  const passwords = inputs.filter((input) => input.type === "password" && input.value !== "");
  const password = passwords[0];
  if (password === undefined || passwords.length !== 1) return null;
  if (tokens(password).some((token) => token === "new-password" || token === "one-time-code")) {
    return null;
  }
  const named = inputs.find((input) => tokens(input).includes("username") && input.value !== "");
  const before = inputs.slice(0, inputs.indexOf(password));
  const nearest = before.findLast((input) => TEXT_TYPES.has(input.type) && input.value !== "");
  const username = (named ?? nearest)?.value.trim();
  return username ? { username, password: password.value } : null;
}
