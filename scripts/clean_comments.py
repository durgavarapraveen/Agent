import os
import sys
import glob
import tokenize
import ast
from io import BytesIO
import concurrent.futures

def is_commented_code(comment_text):
    # Remove leading hashes and whitespace
    cleaned = comment_text.lstrip('# \t')
    if not cleaned:
        return False
        
    # Heuristic 1: If it contains obvious python keywords followed by space or colon
    # But a better way is to see if it parses as valid python AST, AND it's not just a simple Name or Str.
    try:
        tree = ast.parse(cleaned)
        # If the AST has more than just a single simple node (like a single word 'TODO'), it might be code.
        if not tree.body:
            return False
            
        # If it's just a single name (like a single word comment), ignore
        if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
            if isinstance(tree.body[0].value, ast.Name):
                return False
            # If it's just a string, it's probably a comment written as a string
            if isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
                return False
                
        # If it parses successfully and isn't a simple Name/Str, it's very likely commented out code
        return True
    except SyntaxError:
        return False
    except Exception:
        return False

def evaluate_comments_heuristic(comments, filename):
    return [is_commented_code(c) for c in comments]

def process_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
    except Exception as e:
        print(f"Failed to read {filepath}: {e}")
        return

    try:
        tokens = list(tokenize.tokenize(BytesIO(file_bytes).readline))
    except tokenize.TokenError:
        return

    comments_to_evaluate = []
    comment_tokens = []

    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            if tok.start[0] <= 2 and (tok.string.startswith('#!') or 'coding:' in tok.string or 'coding=' in tok.string):
                continue
            if 'noqa' in tok.string.lower() or 'type: ignore' in tok.string.lower() or 'pylint:' in tok.string.lower():
                continue
                
            comments_to_evaluate.append(tok.string)
            comment_tokens.append(tok)

    if not comments_to_evaluate:
        return
        
    removal_flags = evaluate_comments_heuristic(comments_to_evaluate, filepath)

    if not any(removal_flags):
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for tok, should_remove in zip(comment_tokens, removal_flags):
        if should_remove:
            row, col = tok.start
            line_idx = row - 1
            line = lines[line_idx]
            
            prefix = line[:col]
            if prefix.strip() == "":
                lines[line_idx] = ""
            else:
                lines[line_idx] = prefix.rstrip() + "\n"

    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(lines)
        
    print(f"Cleaned {sum(removal_flags)} comments from {filepath}")


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
                print(f"[{count}/{len(target_files)}] Finished processing a file")
            except Exception as e:
                print(f"File processing failed: {e}")

if __name__ == "__main__":
    main()
