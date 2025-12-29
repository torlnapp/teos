import { defineConfig } from 'repomix';

export default defineConfig({
  output: {
    filePath: 'haruna.repomix.xml',
    style: 'xml',
    compress: false,
    removeEmptyLines: true,
  },
  ignore: {
    customPatterns: [
      '**/.vscode/**',
      'biome.json',
      '**/tests/**',
      '**/*.json',
      '**/.gitignore',
      '**/repomix.config.ts',
    ],
  },
});
