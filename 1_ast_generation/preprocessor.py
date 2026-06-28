import json
import os
import argparse
import shlex
import sys
from pathlib import Path


def find_package_json(package_dir):
    """
    Find package.json in the package root, in a nested package/ directory,
    or recursively under the package directory.
    """
    package_path = Path(package_dir)

    root_package_json = package_path / "package.json"
    if root_package_json.exists():
        return root_package_json

    package_subdir_json = package_path / "package" / "package.json"
    if package_subdir_json.exists():
        return package_subdir_json

    for package_json in package_path.rglob("package.json"):
        if "node_modules" not in package_json.parts:
            return package_json

    return None


def process_package(package_dir):
    """
    Process an NPM package by extracting install-time scripts from package.json
    and converting them into a virtual JavaScript file.

    This guarantees that each package has at least one JavaScript file that can
    be analyzed in later AST/PDCG stages.
    """
    package_path = Path(package_dir)
    js_files = []

    for js_file in package_path.rglob("*.js"):
        if "node_modules" not in js_file.parts:
            js_files.append(str(js_file.absolute()))

    package_json_path = find_package_json(package_dir)
    virtual_file_created = False

    if package_json_path:
        print(f"DEBUG: Found package.json at: {package_json_path}", file=sys.stderr)

        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
                content = f.read()
                print(f"DEBUG: package.json content length: {len(content)}", file=sys.stderr)

            with open(package_json_path, "r", encoding="utf-8") as f:
                package_data = json.load(f)

            scripts = package_data.get("scripts", {})
            print(f"DEBUG: Found scripts: {scripts}", file=sys.stderr)

            target_hooks = ["preinstall", "install", "postinstall"]
            spawn_calls = []

            for hook in target_hooks:
                if hook in scripts:
                    script_command = scripts[hook]
                    print(f"DEBUG: Processing {hook}: {script_command}", file=sys.stderr)

                    if script_command and script_command.strip():
                        converted_calls = convert_script_to_spawn(script_command)
                        print(f"DEBUG: Converted to {len(converted_calls)} spawn calls", file=sys.stderr)
                        spawn_calls.extend(converted_calls)

            if spawn_calls:
                virtual_file_path = package_path / "_virtual_behavior_script.js"
                print(
                    f"DEBUG: Creating behavior virtual file with {len(spawn_calls)} calls",
                    file=sys.stderr,
                )

                with open(virtual_file_path, "w", encoding="utf-8") as f:
                    f.write("// Virtual behavior script generated from package.json install scripts\n")
                    f.write("// This file captures install-time behavior for later analysis\n")
                    f.write("const { spawn } = require('child_process');\n\n")
                    for i, call in enumerate(spawn_calls, 1):
                        f.write(f"// Install command {i}\n")
                        f.write(call + "\n\n")

                js_files.append(str(virtual_file_path.absolute()))
                virtual_file_created = True
                print(f"DEBUG: Behavior virtual file created: {virtual_file_path}", file=sys.stderr)
            else:
                virtual_file_path = package_path / "_virtual_placeholder_script.js"
                print(
                    "DEBUG: No install scripts found, creating placeholder virtual file",
                    file=sys.stderr,
                )

                with open(virtual_file_path, "w", encoding="utf-8") as f:
                    f.write("// Virtual placeholder script generated from package.json\n")
                    f.write("// This file ensures later JS analysis can proceed\n")
                    f.write("// No install scripts were found in package.json\n")
                    f.write("console.log('This is a placeholder virtual file');\n")

                js_files.append(str(virtual_file_path.absolute()))
                virtual_file_created = True
                print(f"DEBUG: Placeholder virtual file created: {virtual_file_path}", file=sys.stderr)

        except json.JSONDecodeError as e:
            print(f"DEBUG: JSON decode error: {e}", file=sys.stderr)
        except Exception as e:
            print(f"DEBUG: Error processing package.json: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
    else:
        print("DEBUG: No package.json found", file=sys.stderr)

    if not js_files or (not virtual_file_created and len(js_files) == 0):
        virtual_file_path = package_path / "_virtual_placeholder_script.js"
        print(
            "DEBUG: No JS files found, creating placeholder virtual file to continue analysis",
            file=sys.stderr,
        )

        with open(virtual_file_path, "w", encoding="utf-8") as f:
            f.write("// Virtual placeholder script\n")
            f.write("// This file ensures later JS analysis can proceed\n")
            f.write("// No package.json or JS files were found in this package\n")
            f.write("console.log('This is a placeholder virtual file for an empty package');\n")

        js_files.append(str(virtual_file_path.absolute()))
        print(f"DEBUG: Empty package placeholder file created: {virtual_file_path}", file=sys.stderr)

    return js_files


def convert_script_to_spawn(script_command):
    """
    Convert a package.json script command into one or more spawn(...) calls.
    """
    print(f"DEBUG: Converting script: {script_command}", file=sys.stderr)

    spawn_calls = []
    commands = script_command.split("&&")

    for command in commands:
        command = command.strip()
        if not command:
            continue

        print(f"DEBUG: Processing command: {command}", file=sys.stderr)

        try:
            parts = shlex.split(command)
            if parts:
                cmd = parts[0]
                args = parts[1:] if len(parts) > 1 else []
                print(f"DEBUG: Command: {cmd}, Args: {args}", file=sys.stderr)

                if args:
                    args_str = ", ".join([repr(arg) for arg in args])
                    spawn_call = f"spawn({repr(cmd)}, [{args_str}]);"
                else:
                    spawn_call = f"spawn({repr(cmd)}, []);"

                spawn_calls.append(spawn_call)
                print(f"DEBUG: Generated spawn call: {spawn_call}", file=sys.stderr)

        except ValueError as e:
            print(f"DEBUG: shlex parsing error: {e}; falling back to simple split", file=sys.stderr)
            parts = command.split()
            if parts:
                cmd = parts[0]
                args = parts[1:] if len(parts) > 1 else []

                if args:
                    args_str = ", ".join([repr(arg) for arg in args])
                    spawn_call = f"spawn({repr(cmd)}, [{args_str}]);"
                else:
                    spawn_call = f"spawn({repr(cmd)}, []);"

                spawn_calls.append(spawn_call)

    return spawn_calls


def main():
    parser = argparse.ArgumentParser(description="NPM package preprocessor")
    parser.add_argument("--package_dir", required=True, help="Path to the NPM package root directory")
    args = parser.parse_args()

    if not os.path.exists(args.package_dir):
        print(f"Error: directory does not exist: {args.package_dir}")
        return

    js_files = process_package(args.package_dir)
    for js_file in js_files:
        print(js_file)


if __name__ == "__main__":
    main()
