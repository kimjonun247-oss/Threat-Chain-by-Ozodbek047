// ESLint for the dashboard sources. The scripts are plain browser scripts that
// share one global scope (see src/types.ts), so cross-file globals are not
// "undefined" -- tsc already checks every name -- and no-undef stays off.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.ts'],
    languageOptions: { sourceType: 'script' },
    rules: {
      'no-undef': 'off',
      // A function or constant defined here and used from another script is not unused.
      '@typescript-eslint/no-unused-vars': ['error', { vars: 'local', args: 'after-used', caughtErrors: 'none' }],
      eqeqeq: ['error', 'smart'],
      'no-var': 'error',
      'prefer-const': 'error',
      // Every innerHTML in these scripts is built with escapeHTML(); keeping the
      // rule in lint output would bury the findings that matter.
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
);
