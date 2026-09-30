// @ts-check

import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';

export default defineConfig(globalIgnores(['worker-configuration.d.ts', '.wrangler/']), {
	files: ['**/*.{js,mjs,ts}'],
	extends: [js.configs.recommended, tseslint.configs.recommended, prettier],
});
