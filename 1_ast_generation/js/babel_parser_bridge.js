const fs = require('fs');
const path = require('path');

let parser;
try {
  // Try to load @babel/parser.
  parser = require('@babel/parser');
} catch (err) {
  console.error('Error: please install @babel/parser with: npm install @babel/parser');
  process.exit(1);
}

/**
 * Parse JavaScript/TypeScript source code with Babel and return an AST.
 *
 * Usage:
 * - first argument: input file path
 * - second argument: output JSON file path (optional)
 */

// Read CLI arguments.
const inputFile = process.argv[2];
const outputFile = process.argv[3];

if (!inputFile) {
  console.error('Error: an input file path is required.');
  process.exit(1);
}

try {
  // Read source code.
  const code = fs.readFileSync(inputFile, 'utf-8');

  // Babel parser options.
  const options = {
    sourceType: 'unambiguous',
    allowImportExportEverywhere: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowUndeclaredExports: true,
    plugins: [
      'jsx',
      'typescript',
      'decorators-legacy',
      'classProperties',
      'dynamicImport',
      'exportDefaultFrom',
      'exportNamespaceFrom',
      'objectRestSpread',
      'optionalChaining',
      'nullishCoalescingOperator'
    ],
    locations: true,
    errorRecovery: true
  };

  // Parse source code.
  const ast = parser.parse(code, options);

  const result = {
    success: true,
    ast: ast
  };

  if (outputFile) {
    fs.writeFileSync(outputFile, JSON.stringify(result, null, 2));
  } else {
    console.log(JSON.stringify(result));
  }

  process.exit(0);
} catch (error) {
  const result = {
    success: false,
    error: {
      message: error.message,
      stack: error.stack,
      loc: error.loc
    }
  };

  if (outputFile) {
    fs.writeFileSync(outputFile, JSON.stringify(result, null, 2));
  } else {
    console.error(JSON.stringify(result));
  }

  process.exit(1);
}
