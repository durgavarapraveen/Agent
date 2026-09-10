import os
import glob
import ast
import concurrent.futures

def process_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
    except Exception as e:
        print(f"Failed to read {filepath}: {e}")
        return

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return

    docstring_ranges = []

    def check_docstring(node):
        if hasattr(node, 'body') and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                # Found a docstring
                start = first.lineno - 1
                end = first.end_lineno
                docstring_ranges.append((start, end))

    check_docstring(tree) # Module docstring
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            check_docstring(node)

    if not docstring_ranges:
        return

    # Sort ranges in descending order so we can delete from bottom up without messing up line numbers
    docstring_ranges.sort(key=lambda x: x[0], reverse=True)

    lines = source.split('\n')
    
    for start, end in docstring_ranges:
        # start is 0-indexed line where docstring starts
        # end is 1-indexed line where docstring ends
        # So we delete lines from `start` to `end - 1`
        del lines[start:end]

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"Removed {len(docstring_ranges)} docstrings from {filepath}")

def main():
    target_dirs = ["core", "agents", "scripts", "tests", "ui"]
    target_files = []
    
    for py_file in glob.glob("*.py"):
        target_files.append(py_file)
        
    for d in target_dirs:
        for root, _, files in os.walk(d):
            if '.venv' in root or '__pycache__' in root:
                continue
            for file in files:
                if file.endswith(".py"):
                    target_files.append(os.path.join(root, file))

    print(f"Found {len(target_files)} python files.")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_file, filepath) for filepath in target_files]
        for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
            try:
                future.result()
            except Exception as e:
                pass

if __name__ == "__main__":
    main()
