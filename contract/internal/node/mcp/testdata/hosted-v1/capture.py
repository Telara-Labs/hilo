"""Capture the eight literal schemas from gateway origin/main without executing Go.

Run with python3 capture.py /absolute/path/to/telara-inference.
Dirty gateway files are never read. Only static Go map/array/scalar literals are
accepted. The independent Go AST compatibility test checks this extraction.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

FUNCTIONS = {
    'taskListDef': 'telara_task_list',
    'taskCreateDef': 'telara_task_create',
    'taskResumeDef': 'telara_task_resume',
    'taskCheckpointDef': 'telara_task_checkpoint',
    'taskPauseDef': 'telara_task_pause',
    'taskCompleteDef': 'telara_task_complete',
    'knowledgeSearchDef': 'telara_knowledge_search',
    'knowledgeGetContextDef': 'telara_get_context',
}
SOURCE = 'services/mcp-gateway/src/internal/engine/capabilities.go'
TOKEN = re.compile(r'\s+|//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|[A-Za-z_][A-Za-z_0-9]*|-?\d+(?:\.\d+)?|.', re.S)


def schema(function):
    tokens = [m.group() for m in TOKEN.finditer(function)
              if not m.group().isspace() and not m.group().startswith(('//', '/*'))]
    pos = tokens.index('InputSchema') + 2

    def take(want):
        nonlocal pos
        if tokens[pos] != want:
            raise ValueError(f'expected {want}, got {tokens[pos]}')
        pos += 1

    def value():
        nonlocal pos
        token = tokens[pos]
        if token == 'map':
            for item in ('map', '[', 'string', ']', 'any', '{'):
                take(item)
            result = {}
            while tokens[pos] != '}':
                key = value()
                take(':')
                if key in result:
                    raise ValueError('duplicate schema key')
                result[key] = value()
                if tokens[pos] == ',':
                    pos += 1
                elif tokens[pos] != '}':
                    raise ValueError('missing comma')
            take('}')
            return result
        if token == '[':
            take('[')
            take(']')
            element = tokens[pos]
            if element not in ('string', 'any'):
                raise ValueError('unsupported schema array')
            pos += 1
            take('{')
            result = []
            while tokens[pos] != '}':
                result.append(value())
                if tokens[pos] == ',':
                    pos += 1
                elif tokens[pos] != '}':
                    raise ValueError('missing comma')
            take('}')
            return result
        pos += 1
        if token.startswith('"'):
            result = json.loads(token)
        elif token.startswith('`'):
            result = token[1:-1].replace('\r', '')
        elif token in ('true', 'false'):
            result = token == 'true'
        elif re.fullmatch(r'-?\d+(?:\.\d+)?', token):
            result = json.loads(token)
        else:
            raise ValueError(f'unsupported schema expression {token}')
        if tokens[pos] == '+':
            pos += 1
            right = value()
            if not isinstance(result, str) or not isinstance(right, str):
                raise ValueError('only string concatenation is supported')
            result += right
        return result

    return value()


def main():
    repo = Path(sys.argv[1]).resolve()
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'origin/main'], text=True).strip()
    raw = subprocess.check_output(['git', '-C', str(repo), 'show', 'origin/main:' + SOURCE])
    pinned = subprocess.check_output(['git', '-C', str(repo), 'show', commit + ':' + SOURCE])
    if raw != pinned:
        raise RuntimeError('origin/main moved during capture; rerun')
    text = raw.decode()
    schemas = {}
    for function, tool in FUNCTIONS.items():
        start = text.index('func ' + function + '() ToolDef {')
        end = text.index('\n}\n', start) + 3
        schemas[tool] = schema(text[start:end])
    base = Path(__file__).parent
    (base / 'input-schemas.json').write_text(json.dumps(schemas, indent=2, sort_keys=True) + '\n')
    (base / 'provenance.json').write_text(json.dumps({
        'version': 2, 'repository': 'telara-inference', 'ref': 'origin/main',
        'commit': commit, 'source': SOURCE,
        'source_sha256': hashlib.sha256(raw).hexdigest(),
        'functions': list(FUNCTIONS),
        'capture': 'literal source definitions, not live tools/list',
    }, indent=2) + '\n')
    runtime = base.parent.parent.parent / 'mcpcatalog' / 'schemas_data.go'
    runtime.write_text('// Code generated from gateway literal input schemas by mcp/testdata/hosted-v1/capture.py.\n'
                       '// Regenerate only when intentionally updating hosted compatibility.\n'
                       'package mcpcatalog\n\nconst schemaJSON = `' +
                       json.dumps(schemas, sort_keys=True, separators=(',', ':')) + '`\n')


if __name__ == '__main__':
    main()
