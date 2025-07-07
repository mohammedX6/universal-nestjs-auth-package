const js = require('@eslint/js');
const typescript = require('@typescript-eslint/eslint-plugin');
const typescriptParser = require('@typescript-eslint/parser');
const prettier = require('eslint-plugin-prettier');
const prettierConfig = require('eslint-config-prettier');
const globals = require('globals');

module.exports = [
  // Apply to all files
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.es2022,
      },
    },
    linterOptions: {
      reportUnusedDisableDirectives: true,
    },
  },
  
  // JavaScript files
  {
    files: ['**/*.js', '**/*.mjs'],
    ...js.configs.recommended,
  },
  
  // TypeScript files
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: typescriptParser,
      parserOptions: {
        project: ['./tsconfig.json', './tsconfig.build.json'],
        tsconfigRootDir: __dirname,
        sourceType: 'module',
        ecmaVersion: 2022,
      },
      globals: {
        ...globals.node,
        ...globals.jest,
      },
    },
    plugins: {
      '@typescript-eslint': typescript,
      prettier: prettier,
    },
    rules: {
      // Base ESLint rules
      ...js.configs.recommended.rules,
      
      // TypeScript ESLint recommended rules
      ...typescript.configs.recommended.rules,
      
      // Prettier integration
      ...prettierConfig.rules,
      'prettier/prettier': 'error',
      
      // TypeScript specific rules
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_|^error$|^userId$|^fingerprint$|^currentToken$|^fallbackError$',
          varsIgnorePattern: '^_|^AuthStats$',
          caughtErrorsIgnorePattern: '^_|^error$|^fallbackError$',
        },
      ],
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/interface-name-prefix': 'off',
      '@typescript-eslint/no-namespace': 'off', // Allow for Express global namespace
      '@typescript-eslint/prefer-nullish-coalescing': 'off', // Requires strictNullChecks
      '@typescript-eslint/prefer-optional-chain': 'off',
      '@typescript-eslint/consistent-type-definitions': ['error', 'interface'],
      
      // General code quality rules
      'no-console': 'off', // Allow console for logging in NestJS services
      'no-debugger': 'error',
      'no-alert': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-return-await': 'off', // TypeScript version is better
      '@typescript-eslint/return-await': 'error',
      'prefer-const': 'error',
      'prefer-template': 'error',
      'no-var': 'error',
      'object-shorthand': 'error',
      'prefer-arrow-callback': 'error',
      
      // Import/Export rules
      'no-duplicate-imports': 'error',
      
      // NestJS specific adjustments
      '@typescript-eslint/no-inferrable-types': 'off',
      '@typescript-eslint/no-empty-function': 'off',
      '@typescript-eslint/no-parameter-properties': 'off',
      
      // Error handling
      'no-throw-literal': 'error',
      
      // Security
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      
      // Override problematic rules for this codebase
      'no-undef': 'off', // TypeScript handles this
      'no-unreachable': 'warn',
      '@typescript-eslint/ban-ts-comment': 'warn',
    },
  },
  
  // Test files (if any exist in the future)
  {
    files: ['**/*.spec.ts', '**/*.test.ts', '**/test/**/*.ts'],
    languageOptions: {
      globals: {
        ...globals.jest,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      'no-console': 'off',
    },
  },
  
  // Configuration files
  {
    files: ['*.config.{js,ts}', '*.conf.{js,ts}'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-var-requires': 'off',
    },
  },
  
  // Ignore patterns
  {
    ignores: [
      'dist/**',
      'build/**',
      'node_modules/**',
      '*.config.js',
      '*.config.mjs',
      'coverage/**',
      '.nyc_output/**',
      'temp/**',
      'tmp/**',
    ],
  },
]; 