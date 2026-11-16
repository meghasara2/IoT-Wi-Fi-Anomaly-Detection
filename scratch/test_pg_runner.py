"""
PostgreSQL 16 Standalone Runner Test for Stage 3B.6 Golden Cloud Schema Migration.
"""
import tempfile
import os
import subprocess
import shutil
import re
from pathlib import Path

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
            if sql_text[i:i+2] == '--':
                end = sql_text.find('\n', i)
                if end == -1:
                    break
                result.append('\n')
                i = end + 1
                continue
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

def parse_sql_statements(sql_text):
    """
    Parses a PostgreSQL SQL script into standalone single-line statements
    suitable for standalone single-user mode (postgres --single), properly
    respecting dollar-quoted blocks ($$...$$ or $tag$...$tag$) and string literals.
    """
    clean_sql = strip_sql_comments(sql_text)
    
    stmts = []
    current = []
    in_dollar = False
    dollar_tag = ''
    in_str = False
    
    i = 0
    n = len(clean_sql)
    while i < n:
        c = clean_sql[i]
        
        # Check string literal
        if not in_dollar and c == "'":
            if in_str and i + 1 < n and clean_sql[i+1] == "'":
                current.append("''")
                i += 2
                continue
            in_str = not in_str
            current.append(c)
            i += 1
            continue
            
        # Check dollar-quoting
        if not in_str and c == '$':
            m = re.match(r'(\$[a-zA-Z0-9_]*\$)', clean_sql[i:])
            if m:
                tag = m.group(1)
                if in_dollar and tag == dollar_tag:
                    in_dollar = False
                    dollar_tag = ''
                elif not in_dollar:
                    in_dollar = True
                    dollar_tag = tag
                current.append(tag)
                i += len(tag)
                continue
                
        # Check statement terminator
        if not in_str and not in_dollar and c == ';':
            current.append(';')
            stmt = ''.join(current).strip()
            if stmt:
                clean_stmt = ' '.join(stmt.split())
                stmts.append(clean_stmt)
            current = []
            i += 1
            continue
            
        current.append(c)
        i += 1
        
    leftover = ''.join(current).strip()
    if leftover:
        stmts.append(' '.join(leftover.split()))
        
    return stmts
