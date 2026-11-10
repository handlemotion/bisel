# Changelog

## [0.1.7](https://github.com/handlemotion/bisel/compare/v0.1.6...v0.1.7) (2026-11-10)


### Bug Fixes

* ship releases without a manual step; retry hdiutil's transient busy error ([#57](https://github.com/handlemotion/bisel/issues/57)) ([1c9c00f](https://github.com/handlemotion/bisel/commit/1c9c00fbc57affd858ed6bb307b4c9502976a664))
* the release watcher only ships a draft newer than the latest release ([#59](https://github.com/handlemotion/bisel/issues/59)) ([b46ad27](https://github.com/handlemotion/bisel/commit/b46ad2766b25b3efa66548fd6a54a5ce545e0b1a))
* unlock from the command panel falls back to the system Touch ID prompt, and key errors read plainly ([#60](https://github.com/handlemotion/bisel/issues/60)) ([15b859d](https://github.com/handlemotion/bisel/commit/15b859d17e5c4007dc89bdf098fcf7181bd2d014))

## [0.1.6](https://github.com/handlemotion/bisel/compare/v0.1.5...v0.1.6) (2026-11-06)


### Features

* add the passkey engine to BiselCore ([#47](https://github.com/handlemotion/bisel/issues/47)) ([87bbbb9](https://github.com/handlemotion/bisel/commit/87bbbb9976fc38e9fe5de48fee0fef3a14273220))
* fill one-time codes through AutoFill ([#53](https://github.com/handlemotion/bisel/issues/53)) ([cada6cc](https://github.com/handlemotion/bisel/commit/cada6ccaf834a388bd593d17d215665b17988205))
* offer to save logins from Chrome ([#54](https://github.com/handlemotion/bisel/issues/54)) ([35e27f7](https://github.com/handlemotion/bisel/commit/35e27f79b6fcd605bb2ff9e5dc0947750908ed9a))
* select rows by click and reopen the panel where it was left ([#56](https://github.com/handlemotion/bisel/issues/56)) ([f0b104e](https://github.com/handlemotion/bisel/commit/f0b104e0ad1233142a84331bdf05b091a97a00be))
* sign in and register passkeys through AutoFill ([#50](https://github.com/handlemotion/bisel/issues/50)) ([c08fced](https://github.com/handlemotion/bisel/commit/c08fcedc5a216444375c7978cd035c20e46d4c6f))
* system AutoFill extension for passwords ([#48](https://github.com/handlemotion/bisel/issues/48)) ([a936e6d](https://github.com/handlemotion/bisel/commit/a936e6d4db623dfd900521ecf411978de70fc3bf))
* unlock with Touch ID inside the locked panel ([#51](https://github.com/handlemotion/bisel/issues/51)) ([f6e6cad](https://github.com/handlemotion/bisel/commit/f6e6cadc358ab2ec2bdf99c69926e4ccd071053b))


### Bug Fixes

* keep the Dock icon away once every window is closed ([#52](https://github.com/handlemotion/bisel/issues/52)) ([c2f8bb2](https://github.com/handlemotion/bisel/commit/c2f8bb2ef014ea53c890442f42d7fccdb574b1a2))

## [0.1.5](https://github.com/handlemotion/bisel/compare/v0.1.4...v0.1.5) (2026-11-05)


### Features

* create logins from the command panel ([#45](https://github.com/handlemotion/bisel/issues/45)) ([f6b8a17](https://github.com/handlemotion/bisel/commit/f6b8a17b804c84ee0b56c97ccd97610d3b710659))


### Bug Fixes

* run only one production copy of Bisel ([#44](https://github.com/handlemotion/bisel/issues/44)) ([d4c4abb](https://github.com/handlemotion/bisel/commit/d4c4abb8bae846c64fa37ca0c39748dcbb9ba0df))


### Performance Improvements

* faster unlock, panel and far rows on large boxes ([#42](https://github.com/handlemotion/bisel/issues/42)) ([f367d8b](https://github.com/handlemotion/bisel/commit/f367d8bc12740af4c4e725a26aeea159cae105e4))

## [0.1.4](https://github.com/handlemotion/bisel/compare/v0.1.3...v0.1.4) (2026-11-04)


### Features

* agent CLI that uses box items without reading them ([#36](https://github.com/handlemotion/bisel/issues/36)) ([63dc672](https://github.com/handlemotion/bisel/commit/63dc672770e9f01b21dd5d4639cbde11a31b9f07))


### Bug Fixes

* build FakeHome on the Xcode 26.6 that CodeQL Swift uses ([#39](https://github.com/handlemotion/bisel/issues/39)) ([3a57920](https://github.com/handlemotion/bisel/commit/3a57920f92cd9166afb91d43580470521da6f21c))
* keep the update feed on the last release until the new one has its assets ([#40](https://github.com/handlemotion/bisel/issues/40)) ([054b777](https://github.com/handlemotion/bisel/commit/054b777212027726bac71b25439dad1b4fa6a8c8))
* panel lists every item A to Z, and items can be trashed and recovered ([#37](https://github.com/handlemotion/bisel/issues/37)) ([57c768b](https://github.com/handlemotion/bisel/commit/57c768beebbc1ff3ce88a20639c9383678de8378))

## [0.1.3](https://github.com/handlemotion/bisel/compare/v0.1.2...v0.1.3) (2026-11-02)


### Features

* native Settings window with a sidebar ([#32](https://github.com/handlemotion/bisel/issues/32)) ([26de49e](https://github.com/handlemotion/bisel/commit/26de49efaaa8ce3bcd57ff25fd57dec299742744))


### Bug Fixes

* Settings sidebar starts wider and never closes ([fcfd7a4](https://github.com/handlemotion/bisel/commit/fcfd7a4bbd1398b1234abdc081b5b73d48c34915))

## [0.1.2](https://github.com/handlemotion/bisel/compare/v0.1.1...v0.1.2) (2026-11-01)


### Features

* in-app updates with Sparkle ([21d8bf2](https://github.com/handlemotion/bisel/commit/21d8bf2201b946eea37befe82b5b65d05001644d))

## [0.1.1](https://github.com/handlemotion/bisel/compare/v0.1.0...v0.1.1) (2026-11-01)


### Features

* Fill-is-off tab under the panel and a full-panel No matches state ([8964015](https://github.com/handlemotion/bisel/commit/89640156f80b07618258d00ae97004989c00db55))
* panel empty states, ⌘, for Settings, and the Bisel mark in the menu bar ([#24](https://github.com/handlemotion/bisel/issues/24)) ([eb97d9c](https://github.com/handlemotion/bisel/commit/eb97d9cca7a82b2f79bbf41f7812b3b9d332a321))
