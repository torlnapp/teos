import { defineConfig } from 'repomix';

export default defineConfig({
  output: {
    filePath: 'teos.repomix.xml',
    style: 'xml',
    compress: true,
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
