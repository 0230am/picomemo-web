import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const root = path.dirname(fileURLToPath(import.meta.url));
export default defineConfig({
    root,
    build: { outDir: path.join(root, "dist"), emptyOutDir: true, assetsInlineLimit: 0 },
    worker: { format: "es" },
});

