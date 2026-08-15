import pkg from "../package.json" with { type: "json" };

const expected = `v${pkg.version}`;
if (process.env.RELEASE_TAG !== expected) {
  throw new Error(
    `release tag does not match package version: expected ${expected}, received ${process.env.RELEASE_TAG ?? "nothing"}`,
  );
}
