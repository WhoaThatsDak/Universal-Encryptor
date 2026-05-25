import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  base: "/Universal-Encryptor/",
  build: {
    outDir: "docs"
  },
  plugins: [svelte()]
});
