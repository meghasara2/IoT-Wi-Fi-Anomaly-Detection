"""
Fix comment stripping inside dollar-quoted DO blocks.
"""
import re

def strip_sql_comments(sql_text):
    """
    Strips single-line and block comments from SQL text,
    EVEN inside dollar-quoted PL/pgSQL blocks, while preserving
    string literals.
    """
    result = []
    i = 0
    n = len(sql_text)
    in_str = False
    
    while i < n:
        # String literal check
        if sql_text[i] == "'":
            if in_str and i + 1 < n and sql_text[i+1] == "'":
                result.append("''")
                i += 2
                continue
            in_str = not in_str
            result.append("'")
            i += 1
            continue
            
        if not in_str:
            # Single-line comment
            if sql_text[i:i+2] == '--':
                end = sql_text.find('\n', i)
                if end == -1:
                    break
                result.append('\n')
                i = end + 1
                continue
            # Multi-line comment
            if sql_text[i:i+2] == '/*':
                end = sql_text.find('*/', i+2)
                if end == -1:
                    break
                result.append(' ')
                i = end + 2
                continue
                
        result.append(sql_text[i])
        i += 1
        
    return ''.join(result)

if __name__ == '__main__':
    with open('scratch/stage3b_6_final_supabase_migration.sql', 'r', encoding='utf-8') as f:
        raw = f.read()
    clean = strip_sql_comments(raw)
    print("Stripped comments. Original len:", len(raw), "Clean len:", len(clean))
