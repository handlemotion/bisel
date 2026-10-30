/** @type {import('lint-staged').Configuration} */
export default {
  "*.{js,mjs,cjs,ts,json,jsonc,md}": "oxfmt --no-error-on-unmatched-pattern",
  "*.{js,mjs,cjs,ts}": "oxlint --fix",
  // Advisory for now: the existing Swift code predates swift-format. Warnings do not block a commit.
  "*.swift": "xcrun swift-format lint --configuration apps/mac/.swift-format",
};
