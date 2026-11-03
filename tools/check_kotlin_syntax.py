#!/usr/bin/env python3
"""Rough Kotlin delimiter-balance checker: tokenizes out strings, char literals,
line comments, block comments, and raw strings, then verifies (), {}, [] balance."""
import sys, re, os

def check(path):
    with open(path, 'r', encoding='utf-8') as f:
        src = f.read()
    i, n = 0, len(src)
    stack = []
    line = 1
    errors = []
    state = None  # None | 'line_comment' | 'block_comment' | 'string' | 'rawstring' | 'char'
    while i < n:
        c = src[i]
        if c == '\n':
            line += 1
        if state == 'line_comment':
            if c == '\n':
                state = None
            i += 1
            continue
        if state == 'block_comment':
            if src.startswith('*/', i):
                state = None
                i += 2
                continue
            i += 1
            continue
        if state == 'string':
            if c == '\\':
                i += 2
                continue
            if c == '"':
                state = None
            i += 1
            continue
        if state == 'rawstring':
            if src.startswith('"""', i):
                state = None
                i += 3
                continue
            i += 1
            continue
        if state == 'char':
            if c == '\\':
                i += 2
                continue
            if c == "'":
                state = None
            i += 1
            continue
        # normal state
        if src.startswith('//', i):
            state = 'line_comment'
            i += 2
            continue
        if src.startswith('/*', i):
            state = 'block_comment'
            i += 2
            continue
        if src.startswith('"""', i):
            state = 'rawstring'
            i += 3
            continue
        if c == '"':
            state = 'string'
            i += 1
            continue
        if c == "'":
            state = 'char'
            i += 1
            continue
        if c in '({[':
            stack.append((c, line))
        elif c in ')}]':
            if not stack:
                errors.append(f"line {line}: unmatched '{c}'")
            else:
                open_c, open_line = stack.pop()
                if (open_c == '(' and c != ')') or (open_c == '{' and c != '}') or (open_c == '[' and c != ']'):
                    errors.append(f"line {line}: '{c}' does not match '{open_c}' opened at line {open_line}")
        i += 1
    if state == 'string' or state == 'rawstring':
        errors.append("EOF inside string literal")
    for open_c, open_line in stack:
        errors.append(f"unclosed '{open_c}' opened at line {open_line}")
    return errors

def main():
    root = sys.argv[1]
    bad = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if fn.endswith('.kt') or fn.endswith('.kts'):
                p = os.path.join(dirpath, fn)
                errs = check(p)
                if errs:
                    bad += 1
                    print(f"== {p}")
                    for e in errs:
                        print("   ", e)
    print("DONE:", "ALL BALANCED" if bad == 0 else f"{bad} file(s) with issues")

if __name__ == '__main__':
    main()
