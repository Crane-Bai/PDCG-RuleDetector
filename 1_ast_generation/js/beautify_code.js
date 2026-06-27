const fs = require('fs');

// Read CLI argument (input file path).
const filePath = process.argv[2];

if (!filePath) {
    console.error('Error: a JavaScript file path is required.');
    process.exit(1);
}

try {
    // Read source code.
    const code = fs.readFileSync(filePath, 'utf8');

    // Start with the original source and beautify if possible.
    let beautified = code;

    try {
        // Use js-beautify when available.
        const beautify = require('js-beautify').js;
        beautified = beautify(code, {
            indent_size: 2,
            space_in_empty_paren: true,
            preserve_newlines: true,
            max_preserve_newlines: 2
        });
    } catch (e) {
        // Fallback formatter for environments without js-beautify.
        beautified = code
            .replace(/\{/g, ' {\n  ')
            .replace(/\}/g, '\n}\n')
            .replace(/;/g, ';\n')
            .replace(/\n\s*\n\s*\n/g, '\n\n');
    }

    // Print beautified code to stdout.
    console.log(beautified);

} catch (err) {
    console.error('Error: failed to read or process the file:', err.message);
    process.exit(1);
}
