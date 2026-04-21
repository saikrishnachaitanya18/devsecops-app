// eslint.config.js — minimal config for pre-commit to not error
// Using a permissive setup so vulnerable code doesn't get blocked by lint
export default [
  {
    ignores: ["node_modules/**"],
    rules: {
      // Allow all patterns — this is a demo/training app with intentional bad code
    },
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: "commonjs",
      globals: {
        require: "readonly",
        module: "writable",
        exports: "writable",
        process: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        console: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
      },
    },
  },
];
