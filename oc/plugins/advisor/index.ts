// V2 package entrypoint. Local plugin directories resolve at the package
// root (index.ts); package.json "main" is ignored and file-path config
// entries are rejected, so this file only re-exports the implementation.
// The .js extension maps to advisor.ts under the host's TS loader.
export { default } from "./src/advisor.js";
