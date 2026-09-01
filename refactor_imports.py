import os
import re

core_dir = os.path.abspath('core')

# 1. Build the map of module -> subpackage
module_map = {}
for root, dirs, files in os.walk(core_dir):
    for f in files:
        if f.endswith('.py') and not f.startswith('__'):
            mod_name = f[:-3]
            # e.g., root is .../core/common
            subpkg = os.path.basename(root)
            if subpkg != 'core':
                module_map[mod_name] = f"core.{subpkg}.{mod_name}"

# Add any custom mappings if needed
# e.g. tools -> core.tools (but 'tools' is a subpackage itself)
subpackages = {"orchestration", "tools", "intelligence", "exploitation", "memory", "reporting", "security", "common"}

changed_files = 0
for root, dirs, files in os.walk(os.path.abspath('.')):
    if '.gemini' in root or '.git' in root or '__pycache__' in root or 'node_modules' in root or '.venv' in root or 'venv' in root:
        continue
    for f in files:
        if not f.endswith('.py'):
            continue
        filepath = os.path.join(root, f)
        
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
            
        original_content = content
        
        # We want to replace:
        # from core.common.schemas import ... -> from core.common.schemas import ...
        # import core.common.schemas -> import core.common.schemas
        # 
        # But we don't want to mess up already correct imports like:
        # from core.common.schemas import ...
        # 
        # So we look for "core.\w+" and see if the \w+ is in our module_map.
        
        def replacer(match):
            prefix = match.group(1) # 'from ' or 'import '
            mod = match.group(2)    # e.g. 'schemas'
            
            # If it's already a subpackage, don't touch it
            if mod in subpackages:
                return match.group(0)
                
            if mod in module_map:
                # Replace with full path
                return f"{prefix}{module_map[mod]}"
            
            return match.group(0)

        # Regex: (from\s+|import\s+)core\.([a-zA-Z0-9_]+)
        # Matches: from core.common.schemas or import core.common.schemas
        new_content = re.sub(r'(from\s+|import\s+)core\.([a-zA-Z0-9_]+)', replacer, content)
        
        # Also need to handle: from core.common.schemas import *
        # Regex: from\s+core\s+import\s+([a-zA-Z0-9_,\s]+)
        def replacer_from_core(match):
            imports_str = match.group(1)
            imports = [i.strip() for i in imports_str.split(',')]
            
            # If there's a mix, it's complicated. Let's hope it's not.
            # We'll just break it down into multiple lines.
            result_lines = []
            for imp in imports:
                if ' as ' in imp:
                    base_imp = imp.split(' as ')[0].strip()
                    alias = imp.split(' as ')[1].strip()
                else:
                    base_imp = imp
                    alias = None
                    
                if base_imp in module_map:
                    if alias:
                        result_lines.append(f"import {module_map[base_imp]} as {alias}")
                    else:
                        result_lines.append(f"from {module_map[base_imp]} import *") # Actually wait, `from core import schemas` means `schemas` becomes available.
                        # It's better to just do `import core.subpkg.schemas as schemas`
                        result_lines.append(f"import {module_map[base_imp]} as {base_imp}")
                elif base_imp in subpackages:
                    if alias:
                        result_lines.append(f"import core.{base_imp} as {alias}")
                    else:
                        result_lines.append(f"import core.{base_imp} as {base_imp}")
                else:
                    # fallback
                    result_lines.append(f"from core import {imp}")
            
            return "\n".join(result_lines)
            
        new_content = re.sub(r'from\s+core\s+import\s+([a-zA-Z0-9_,\s]+)(?=\n|$)', replacer_from_core, new_content)

        if new_content != original_content:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(new_content)
            changed_files += 1
            print(f"Updated {filepath}")

print(f"Total files updated: {changed_files}")
