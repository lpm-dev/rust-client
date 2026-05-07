// Minimal ESLint flat config exercising plugin imports.
// If hoisted layout breaks plugin discovery, ESLint fails to load the
// config (parser or plugin import error).
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import reactHooks from "eslint-plugin-react-hooks";

export default [
	{
		files: ["**/*.{js,ts,jsx,tsx}"],
		languageOptions: {
			parser: tsParser,
		},
		plugins: {
			"@typescript-eslint": tsPlugin,
			"react-hooks": reactHooks,
		},
		rules: {
			"@typescript-eslint/no-unused-vars": "warn",
			"react-hooks/rules-of-hooks": "error",
		},
	},
];
