import os
import sys
import json
import tempfile
import subprocess
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# Configure console encoding to UTF-8
sys.stdout.reconfigure(encoding='utf-8')
os.system('chcp 65001 >nul')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SelectiveAstGenerator:
    """Selective AST Generator - Supports processing benign/malicious separately or direct processing mode"""
    
    def __init__(self, input_dir: Optional[str] = None, output_dir: Optional[str] = None, skip_existing: bool = False):
        # Use custom directories if provided; otherwise use default paths
        if input_dir:
            self.extracted_dir = Path(input_dir)
        else:
            self.extracted_dir = Path(r'...')
        
        if output_dir:
            self.ast_dir = Path(output_dir)
        else:
            self.ast_dir = Path(r'...')
        
        self.bridge_script = self._get_bridge_script_path()
        self.skip_existing = skip_existing  # Whether to skip existing AST files
        
        # Create AST directory
        self.ast_dir.mkdir(parents=True, exist_ok=True)
        # In direct mode, directories are created based on actual package names
        
    def _get_bridge_script_path(self) -> str:
        """Get the Node.js bridge script path"""
        script_dir = Path(__file__).parent / 'js'
        return str(script_dir / 'babel_parser_bridge.js')
    
    def _create_bridge_script(self):
        """Create the Node.js bridge script"""
        script_dir = Path(__file__).parent / 'js'
        script_dir.mkdir(exist_ok=True)
        
        bridge_script_content = '''
const fs = require('fs');

// Use Babel parser
function parseWithBabel(code) {
    const babel = require('@babel/parser');
    return babel.parse(code, {
        sourceType: 'unambiguous',
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true,
        plugins: [
            'jsx',
            'typescript',
            'decorators-legacy',
            'classProperties',
            'objectRestSpread',
            'asyncGenerators',
            'dynamicImport',
            'exportDefaultFrom',
            'exportNamespaceFrom'
        ]
    });
}

// Main function
function main() {
    const inputFile = process.argv[2];
    const outputFile = process.argv[3];
    
    if (!inputFile || !outputFile) {
        console.error('Usage: node babel_parser_bridge.js <input.js> <output.json>');
        process.exit(1);
    }
    
    try {
        const code = fs.readFileSync(inputFile, 'utf8');
        const ast = parseWithBabel(code);
        
        const result = {
            success: true,
            ast: ast,
            parser: 'babel',
            error: null
        };
        
        fs.writeFileSync(outputFile, JSON.stringify(result, null, 2));
        
    } catch (error) {
        const result = {
            success: false,
            ast: null,
            parser: 'babel',
            error: error.message
        };
        fs.writeFileSync(outputFile, JSON.stringify(result, null, 2));
    }
}

main();
'''
        
        bridge_script_path = script_dir / 'babel_parser_bridge.js'
        with open(bridge_script_path, 'w', encoding='utf-8') as f:
            f.write(bridge_script_content)
        
        return str(bridge_script_path)
    
    def _clean_unicode_surrogates(self, obj):
        """Clean Unicode surrogate pair characters"""
        if isinstance(obj, dict):
            return {key: self._clean_unicode_surrogates(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._clean_unicode_surrogates(item) for item in obj]
        elif isinstance(obj, str):
            # Remove invalid Unicode surrogate pairs
            try:
                # Try encoding to UTF-8, clean if fails
                obj.encode('utf-8')
                return obj
            except UnicodeEncodeError:
                # Remove all surrogate pair characters
                import re
                return re.sub(r'[\ud800-\udfff]', '?', obj)
        else:
            return obj
    
    def generate_ast_for_file(self, js_file_path: Path) -> Tuple[bool, Optional[Dict], str]:
        """Generate AST for a single JS file"""
        try:
            # Check file size (limit 10MB)
            if js_file_path.stat().st_size > 10 * 1024 * 1024:
                return False, None, "File too large (>10MB)"
            
            # Read JS code
            with open(js_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                js_code = f.read()
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(suffix='.js', delete=False, mode='w', encoding='utf-8') as temp_js:
                temp_js_path = temp_js.name
                temp_js.write(js_code)
            
            temp_ast_path = f"{temp_js_path}_ast.json"
            
            try:
                # Ensure bridge script exists
                if not os.path.exists(self.bridge_script):
                    self.bridge_script = self._create_bridge_script()
                
                # Call Node.js script
                result = subprocess.run(
                    ['node', self.bridge_script, temp_js_path, temp_ast_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and os.path.exists(temp_ast_path):
                    with open(temp_ast_path, 'r', encoding='utf-8') as f:
                        result_data = json.load(f)
                    
                    if result_data.get('success'):
                        # Clean Unicode issues in AST
                        clean_ast = self._clean_unicode_surrogates(result_data.get('ast'))
                        return True, clean_ast, 'babel'
                    else:
                        return False, None, result_data.get('error', 'Parsing failed')
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Node.js execution failed"
                    return False, None, error_msg
                    
            finally:
                # Clean up temporary files
                for temp_file in [temp_js_path, temp_ast_path]:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                        
        except Exception as e:
            return False, None, str(e)
    
    def save_ast_or_error(self, ast: Optional[Dict], success: bool, error_reason: str, category: str, package_name: str, relative_js_path: Path) -> str:
        """Save AST to file, or save error information if failed"""
        # Build complete target path, preserving original directory structure
        target_dir = self.ast_dir / category / package_name / relative_js_path.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate AST filename: original_filename.ast.json
        ast_filename = f"{relative_js_path.name}.ast.json"
        ast_file_path = target_dir / ast_filename
        
        if success and ast:
            # Save successful AST
            ast_data = {
                "success": True,
                "parser": "babel",
                "ast": ast,
                "error": None
            }
        else:
            # Save failure information
            ast_data = {
                "success": False,
                "parser": "babel",
                "ast": None,
                "error": error_reason
            }
        
        # Clean Unicode issues in all data
        clean_ast_data = self._clean_unicode_surrogates(ast_data)
        
        try:
            # Save to file using safer encoding
            with open(ast_file_path, 'w', encoding='utf-8', errors='replace') as f:
                json.dump(clean_ast_data, f, ensure_ascii=False, indent=2)
        except UnicodeEncodeError:
            # If still problematic, use ASCII encoding
            with open(ast_file_path, 'w', encoding='utf-8') as f:
                json.dump(clean_ast_data, f, ensure_ascii=True, indent=2)
        
        return str(ast_file_path)
    
    def _get_javascript_files(self, directory: Path) -> list:
        """Get all JavaScript files (.js, .cjs, .mjs) under directory, excluding directories with these extensions"""
        js_files = []
        for pattern in ["*.js", "*.cjs", "*.mjs"]:
            # Use rglob for recursive search, but only include files, exclude directories
            js_files.extend([f for f in directory.rglob(pattern) if f.is_file()])
        return js_files
    
    def _ast_file_exists(self, category: Optional[str], package_name: str, relative_js_path: Path) -> bool:
        """Check if AST file already exists"""
        if category:
            # Classified mode: ast_dir / category / package_name / relative_js_path.parent / filename.ast.json
            target_dir = self.ast_dir / category / package_name / relative_js_path.parent
        else:
            # Direct mode: ast_dir / package_name / relative_js_path.parent / filename.ast.json
            target_dir = self.ast_dir / package_name / relative_js_path.parent
        
        ast_filename = f"{relative_js_path.name}.ast.json"
        ast_file_path = target_dir / ast_filename
        
        return ast_file_path.exists()
    
    def _is_valid_ast_file(self, category: Optional[str], package_name: str, relative_js_path: Path) -> bool:
        """Check if AST file exists and is valid (contains valid JSON data)"""
        if not self._ast_file_exists(category, package_name, relative_js_path):
            return False
        
        if category:
            target_dir = self.ast_dir / category / package_name / relative_js_path.parent
        else:
            target_dir = self.ast_dir / package_name / relative_js_path.parent
        
        ast_filename = f"{relative_js_path.name}.ast.json"
        ast_file_path = target_dir / ast_filename
        
        try:
            with open(ast_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Check if necessary fields exist
                return isinstance(data, dict) and 'success' in data and 'parser' in data
        except (json.JSONDecodeError, IOError, UnicodeDecodeError):
            return False
    
    def get_category_stats(self, category: str) -> Dict[str, int]:
        """Get statistics for specified category"""
        category_dir = self.extracted_dir / category
        
        if not category_dir.exists():
            return {'packages': 0, 'js_files': 0}
        
        packages = 0
        js_files = 0
        
        for package_dir in category_dir.iterdir():
            if package_dir.is_dir():
                packages += 1
                # Use helper method to get JavaScript files
                js_files += len(self._get_javascript_files(package_dir))
        
        return {'packages': packages, 'js_files': js_files}
        
        return {'packages': packages, 'js_files': js_files}
    
    def process_category(self, category: str):
        """Process packages for specified category"""
        if category not in ['benign', 'malicious']:
            raise ValueError(f"Invalid category: {category}. Must be 'benign' or 'malicious'")
        
        category_dir = self.extracted_dir / category
        
        if not category_dir.exists():
            print(f"Directory does not exist: {category_dir}")
            return
        
        # Get statistics
        stats = self.get_category_stats(category)
        
        print(f"Starting processing {category.upper()} category")
        print(f"Preview statistics: {stats['packages']} packages, {stats['js_files']} JavaScript files(.js/.cjs/.mjs)")
        print(f"Using parser: @babel/parser")
        print(f"Preserving full directory structure...")
        print("="*60)
        
        # Create a dedicated log file to record all failures
        failure_log_path = self.ast_dir / f"ast_generation_failures_{category}.log"
        with open(failure_log_path, 'w', encoding='utf-8') as f:
            f.write(f"--- {category.upper()} Category AST Generation Failure Report ---\n\n")
        
        total_files = 0
        success_count = 0
        failed_count = 0
        skipped_count = 0
        failed_files = []
        processed_packages = 0
        
        # Iterate through packages
        for package_dir in category_dir.iterdir():
            if not package_dir.is_dir():
                continue
            
            package_name = package_dir.name
            processed_packages += 1
            
            print(f"\n[{processed_packages}/{stats['packages']}] Processing package: {category}/{package_name}")
            
            # Use helper method to find all JavaScript files (.js, .cjs, .mjs), excluding directories with these extensions
            js_files = self._get_javascript_files(package_dir)
            
            if not js_files:
                print(f"   No JavaScript files found")
                continue
            
            print(f"   Found {len(js_files)} JavaScript files")
            
            for i, js_file in enumerate(js_files, 1):
                total_files += 1
                
                # Generate relative path (preserve directory structure)
                relative_path = js_file.relative_to(package_dir)
                
                print(f"   [{i}/{len(js_files)}] Processing: {relative_path}")
                
                # If skip-existing option is enabled, check if AST file already exists
                if self.skip_existing and self._is_valid_ast_file(category, package_name, relative_path):
                    skipped_count += 1
                    print(f"      Skipped (AST already exists)")
                    continue
                
                # Generate AST
                success, ast, info = self.generate_ast_for_file(js_file)
                
                # Save results regardless of success or failure
                try:
                    ast_path = self.save_ast_or_error(ast, success, info, category, package_name, relative_path)
                    
                    if success and ast:
                        success_count += 1
                        print(f"      AST saved successfully")
                    else:
                        failed_count += 1
                        failed_files.append({
                            'file': f"{category}/{package_name}/{relative_path}",
                            'reason': info,
                            'category': category,
                            'package': package_name,
                            'relative_path': str(relative_path)
                        })
                        print(f"      Failed: {info}")
                except Exception as e:
                    failed_count += 1
                    error_msg = f"Save failed: {str(e)}"
                    failed_files.append({
                        'file': f"{category}/{package_name}/{relative_path}",
                        'reason': error_msg,
                        'category': category,
                        'package': package_name,
                        'relative_path': str(relative_path)
                    })
                    print(f"      Save failed: {error_msg}")
        
        # Output detailed statistics and pass log file path
        self._print_category_summary(category, total_files, success_count, failed_count, skipped_count, failed_files, processed_packages, failure_log_path)
    
    def _print_category_summary(self, category: str, total_files: int, success_count: int, 
                                   failed_count: int, skipped_count: int, failed_files: list, processed_packages: int,
                                   failure_log_path: Path):
        """Print category processing summary and write complete failure list to log file"""
        summary_lines = [
            "\n" + "="*80,
            f"{category.upper()} Category Processing Complete",
            "="*80,
            f"Processed packages: {processed_packages}",
            f"Total files: {total_files}",
            f"Successfully generated: {success_count}",
            f"Failed: {failed_count}",
        ]
        
        # Add skip statistics if there are skipped files
        if skipped_count > 0:
            summary_lines.append(f"Skipped (already exists): {skipped_count}")
        
        # Calculate processed files (total files minus skipped files)
        processed_files = total_files - skipped_count
        if processed_files > 0:
            summary_lines.append(f"Success rate: {(success_count/processed_files*100):.1f}%")
        else:
            summary_lines.append("Success rate: 0%")
        
        summary_lines.append(f"\nComplete failure file list saved to: {failure_log_path}")
        
        print("\n".join(summary_lines))
        
        if failed_files:
            # Group by reason
            reasons = {}
            for failed in failed_files:
                reason = failed['reason']
                if reason not in reasons:
                    reasons[reason] = []
                reasons[reason].append(failed)
            
            # Write complete, unabridged list to log file
            with open(failure_log_path, 'a', encoding='utf-8') as f:
                f.write("\n--- Failure Reason Detailed Analysis ---\n")
                # Sort reasons by number of failed files
                for reason, files in sorted(reasons.items(), key=lambda item: len(item[1]), reverse=True):
                    f.write(f"\nReason: [{reason}] - {len(files)} files\n")
                    for file_info in files:
                        f.write(f"   - {file_info['file']}\n")
    
            # Print a short preview in console
            print(f"\nConsole failure reason preview (see log file for complete list):")
            # Sort reasons by number of failed files
            for reason, files in sorted(reasons.items(), key=lambda item: len(item[1]), reverse=True)[:5]: # Preview top 5 reasons only
                print(f"\n[{reason}] - {len(files)} files:")
                for file_info in files[:3]: # Preview top 3 for each reason
                    print(f"   - {file_info['file']}")
                if len(files) > 3:
                    print(f"   ... (and {len(files) - 3} other files)")

    def process_both_categories(self):
        """Process all categories"""
        print("Starting processing all JS files, generating AST...")
        
        # Ensure benign and malicious subdirectories are created
        (self.ast_dir / 'benign').mkdir(exist_ok=True)
        (self.ast_dir / 'malicious').mkdir(exist_ok=True)
        
        for category in ['benign', 'malicious']:
            self.process_category(category)
        
        print(f"\nAll categories processing complete!")
    
    def get_direct_stats(self) -> Dict[str, int]:
        """Get statistics for direct mode"""
        if not self.extracted_dir.exists():
            return {'packages': 0, 'js_files': 0}
        
        packages = 0
        js_files = 0
        
        for package_dir in self.extracted_dir.iterdir():
            if package_dir.is_dir():
                packages += 1
                # Use helper method to get JavaScript files
                js_files += len(self._get_javascript_files(package_dir))
        
        return {'packages': packages, 'js_files': js_files}
    
    def process_direct_mode(self):
        """Direct processing mode - Process all packages under specified directory without benign/malicious classification"""
        if not self.extracted_dir.exists():
            print(f"Input directory does not exist: {self.extracted_dir}")
            return
        
        # Get statistics
        stats = self.get_direct_stats()
        
        print(f"Starting direct processing mode")
        print(f"Input directory: {self.extracted_dir}")
        print(f"Output directory: {self.ast_dir}")
        print(f"Preview statistics: {stats['packages']} packages, {stats['js_files']} JavaScript files(.js/.cjs/.mjs)")
        print(f"Using parser: @babel/parser")
        print(f"Preserving full directory structure...")
        print("="*60)
        
        # Create a dedicated log file to record all failures
        failure_log_path = self.ast_dir / "ast_generation_failures_direct.log"
        with open(failure_log_path, 'w', encoding='utf-8') as f:
            f.write("--- Direct Mode AST Generation Failure Report ---\n\n")
        
        total_files = 0
        success_count = 0
        failed_count = 0
        skipped_count = 0
        failed_files = []
        processed_packages = 0
        
        # Iterate through packages
        for package_dir in self.extracted_dir.iterdir():
            if not package_dir.is_dir():
                continue
            
            package_name = package_dir.name
            processed_packages += 1
            
            print(f"\n[{processed_packages}/{stats['packages']}] Processing package: {package_name}")
            
            # Use helper method to find all JavaScript files (.js, .cjs, .mjs), excluding directories with these extensions
            js_files = self._get_javascript_files(package_dir)
            
            if not js_files:
                print(f"   No JavaScript files found")
                continue
            
            print(f"   Found {len(js_files)} JavaScript files")
            
            for i, js_file in enumerate(js_files, 1):
                total_files += 1
                
                # Generate relative path (preserve directory structure)
                relative_path = js_file.relative_to(package_dir)
                
                print(f"   [{i}/{len(js_files)}] Processing: {relative_path}")
                
                # If skip-existing option is enabled, check if AST file already exists (direct mode does not use category)
                if self.skip_existing and self._is_valid_ast_file(None, package_name, relative_path):
                    skipped_count += 1
                    print(f"      Skipped (AST already exists)")
                    continue
                
                # Generate AST
                success, ast, info = self.generate_ast_for_file(js_file)
                
                # Save results regardless of success or failure
                try:
                    # In direct mode, do not use category classification, use package name as top-level directory
                    ast_path = self.save_ast_or_error_direct(ast, success, info, package_name, relative_path)
                    
                    if success and ast:
                        success_count += 1
                        print(f"      AST saved successfully")
                    else:
                        failed_count += 1
                        failed_files.append({
                            'file': f"{package_name}/{relative_path}",
                            'reason': info,
                            'package': package_name,
                            'relative_path': str(relative_path)
                        })
                        print(f"      Failed: {info}")
                except Exception as e:
                    failed_count += 1
                    error_msg = f"Save failed: {str(e)}"
                    failed_files.append({
                        'file': f"{package_name}/{relative_path}",
                        'reason': error_msg,
                        'package': package_name,
                        'relative_path': str(relative_path)
                    })
                    print(f"      Save failed: {error_msg}")
        
        # Output detailed statistics
        self._print_direct_summary(total_files, success_count, failed_count, skipped_count, failed_files, processed_packages, failure_log_path)
    
    def save_ast_or_error_direct(self, ast: Optional[Dict], success: bool, error_reason: str, package_name: str, relative_js_path: Path) -> str:
        """Save AST to file in direct mode, or save error information if failed"""
        # Build complete target path, preserving original directory structure, without category classification
        target_dir = self.ast_dir / package_name / relative_js_path.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate AST filename: original_filename.ast.json
        ast_filename = f"{relative_js_path.name}.ast.json"
        ast_file_path = target_dir / ast_filename
        
        if success and ast:
            # Save successful AST
            ast_data = {
                "success": True,
                "parser": "babel",
                "ast": ast,
                "error": None
            }
        else:
            # Save failure information
            ast_data = {
                "success": False,
                "parser": "babel",
                "ast": None,
                "error": error_reason
            }
        
        # Clean Unicode issues in all data
        clean_ast_data = self._clean_unicode_surrogates(ast_data)
        
        try:
            # Save to file using safer encoding
            with open(ast_file_path, 'w', encoding='utf-8', errors='replace') as f:
                json.dump(clean_ast_data, f, ensure_ascii=False, indent=2)
        except UnicodeEncodeError:
            # If still problematic, use ASCII encoding
            with open(ast_file_path, 'w', encoding='utf-8') as f:
                json.dump(clean_ast_data, f, ensure_ascii=True, indent=2)
        
        return str(ast_file_path)
    
    def _print_direct_summary(self, total_files: int, success_count: int, 
                             failed_count: int, skipped_count: int, failed_files: list, processed_packages: int,
                             failure_log_path: Path):
        """Print direct mode processing summary and write complete failure list to log file"""
        summary_lines = [
            "\n" + "="*80,
            f"Direct Mode Processing Complete",
            "="*80,
            f"Processed packages: {processed_packages}",
            f"Total files: {total_files}",
            f"Successfully generated: {success_count}",
            f"Failed: {failed_count}",
        ]
        
        # Add skip statistics if there are skipped files
        if skipped_count > 0:
            summary_lines.append(f"Skipped (already exists): {skipped_count}")
        
        # Calculate processed files (total files minus skipped files)
        processed_files = total_files - skipped_count
        if processed_files > 0:
            summary_lines.append(f"Success rate: {(success_count/processed_files*100):.1f}%")
        else:
            summary_lines.append("Success rate: 0%")
        
        summary_lines.append(f"\nComplete failure file list saved to: {failure_log_path}")
        
        print("\n".join(summary_lines))
        
        if failed_files:
            # Group by reason
            reasons = {}
            for failed in failed_files:
                reason = failed['reason']
                if reason not in reasons:
                    reasons[reason] = []
                reasons[reason].append(failed)
            
            # Write complete, unabridged list to log file
            with open(failure_log_path, 'a', encoding='utf-8') as f:
                f.write("\n--- Failure Reason Detailed Analysis ---\n")
                # Sort reasons by number of failed files
                for reason, files in sorted(reasons.items(), key=lambda item: len(item[1]), reverse=True):
                    f.write(f"\nReason: [{reason}] - {len(files)} files\n")
                    for file_info in files:
                        f.write(f"   - {file_info['file']}\n")
        
            # Print a short preview in console
            print(f"\nConsole failure reason preview (see log file for complete list):")
            # Sort reasons by number of failed files
            for reason, files in sorted(reasons.items(), key=lambda item: len(item[1]), reverse=True)[:5]: # Preview top 5 reasons only
                print(f"\n[{reason}] - {len(files)} files:")
                for file_info in files[:3]: # Preview top 3 for each reason
                    print(f"   - {file_info['file']}")
                if len(files) > 3:
                    print(f"   ... (and {len(files) - 3} other files)")

def main():
    """Main function - Supports command line arguments"""
    parser = argparse.ArgumentParser(description='AST Generator - Supports selective processing and direct processing modes')
    parser.add_argument('--mode', '-m',
                       choices=['classified', 'direct'],
                       default='classified',
                       help='Processing mode: classified(process benign/malicious subdirectories), direct(process all packages under specified directory)')
    parser.add_argument('--category', '-c', 
                       choices=['benign', 'malicious', 'both'], 
                       default='both',
                       help='Category to process in classified mode: benign, malicious, both')
    parser.add_argument('--input-dir', '-i',
                       type=str,
                       help='Input directory path (required for direct mode, optional for classified mode)')
    parser.add_argument('--output-dir', '-o',
                       type=str,
                       help='Output directory path (optional, default uses built-in paths)')
    parser.add_argument('--preview', '-p', 
                       action='store_true',
                       help='Preview statistics without actual processing')
    parser.add_argument('--skip-existing', '-s',
                       action='store_true',
                       help='Skip already generated AST files, only process ungenerated parts')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.mode == 'direct' and not args.input_dir:
        print("Direct mode requires --input-dir parameter")
        return
    
    # Create generator instance
    generator = SelectiveAstGenerator(input_dir=args.input_dir, output_dir=args.output_dir, skip_existing=args.skip_existing)
    
    print(f"Processing mode: {args.mode}")
    if args.input_dir:
        print(f"Input directory: {args.input_dir}")
    if args.output_dir:
        print(f"Output directory: {args.output_dir}")
    
    # Preview mode
    if args.preview:
        print("Preview mode - Statistics")
        print("="*50)
        
        if args.mode == 'classified':
            for category in ['benign', 'malicious']:
                stats = generator.get_category_stats(category)
                print(f"{category.upper()}: {stats['packages']} packages, {stats['js_files']} JS files")
        else:  # direct mode
            stats = generator.get_direct_stats()
            print(f"DIRECT: {stats['packages']} packages, {stats['js_files']} JS files")
        
        return
    
    # Execute processing
    if args.mode == 'classified':
        if args.category == 'both':
            generator.process_both_categories()
        else:
            generator.process_category(args.category)
    else:  # direct mode
        generator.process_direct_mode()

if __name__ == "__main__":
    main()