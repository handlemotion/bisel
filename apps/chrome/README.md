# Bisel for Chrome

Offers to save a login to Bisel when you sign in on a website. Saving only: it fills nothing and reads nothing from the box. The design and threat model are in `docs/SPEC.md` §8, "Chrome extension", and `SECURITY.md`, which says plainly that this extension sees passwords as they are typed.

It is not on the Chrome Web Store. The `key` in `public/manifest.json` fixes the extension's ID at `hchnaceebnafpeijdmglkmfccfmlcelj`, which `BrowserLink.extensionID` pins in the app. Change one and the link stops: a test compares them.

## Try it

Chrome launches the native host from a signed app. A notarized build needs only steps 3 to 5. BiselDev runs unsigned, and Chrome cannot pass it the environment that turns the signature check off, so a dev build has to be the signed Debug one:

1. In `apps/mac`, `xcodegen generate`, then build the `Bisel` scheme of `Bisel.xcodeproj` in Debug.
2. Launch it once with `BISEL_DEV_BROWSER_HOST=1` set, which writes the native messaging manifest. A dev build leaves that file alone otherwise. Run the installed app afterwards to point Chrome back at it.
3. `pnpm --filter bisel-chrome build`.
4. In Chrome, open `chrome://extensions`, turn on Developer mode, choose Load unpacked, and pick `apps/chrome/dist`. The ID shown must be the one above.
5. With Bisel running, sign in on an https site. A prompt appears at the top right of the page after the sign-in. Save asks for Touch ID, and the login is in the box. If it does not appear, the login may already be saved, or Bisel may not be running.

To debug the link, start Chrome with `--enable-logging=stderr --log-level=1` and look for `native_messaging`.
