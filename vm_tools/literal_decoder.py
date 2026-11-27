"""Recover text with a finite whitelist of pure transforms; never execute sample code.

This is deliberately a partial constant evaluator, not a Python interpreter.
Imports are symbols only; calls, branches and functions from the sample are not run.
Run this module in the bounded VM worker, not on the host.
"""
from __future__ import annotations

import ast
import base64
from dataclasses import dataclass
import hashlib
import json
import re
import zlib

MAX_BYTES=1_000_000
MAX_NODES=60000
MAX_STEPS=12000


@dataclass(frozen=True)
class Symbol:
    name: str


@dataclass(frozen=True)
class FernetKey:
    key: bytes


class Unsupported(ValueError):
    pass


def bounded(value):
    if isinstance(value,(str,bytes)) and len(value)>MAX_BYTES:
        raise Unsupported('Decoded data exceeds byte limit')
    return value


def parse_source(source):
    bounded(source)
    tree=ast.parse(source)
    if sum(1 for _ in ast.walk(tree))>MAX_NODES:
        raise Unsupported('AST node bound exceeded')
    return tree


def unpack_zlib(data):
    if not isinstance(data,bytes): raise Unsupported('zlib input must be bytes')
    obj=zlib.decompressobj()
    result=obj.decompress(data,MAX_BYTES+1)
    if len(result)>MAX_BYTES or not obj.eof or obj.unused_data:
        raise Unsupported('zlib output exceeds bound, is incomplete, or contains trailing data')
    return result


class Constants:
    def __init__(self):
        self.env={}; self.steps=0; self.transforms=[]

    def value(self,node,depth=0):
        self.steps+=1
        if self.steps>MAX_STEPS or depth>32: raise Unsupported('Expression budget exceeded')
        child=lambda n:self.value(n,depth+1)
        if isinstance(node,ast.Constant) and type(node.value) in (str,bytes,int):
            return bounded(node.value)
        if isinstance(node,ast.Name) and node.id in self.env: return self.env[node.id]
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
            left,right=child(node.left),child(node.right)
            if type(left)==type(right) and isinstance(left,(str,bytes)):
                if len(left)+len(right)>MAX_BYTES: raise Unsupported('Concatenation bound')
                return left+right
        if isinstance(node,ast.Attribute):
            base=child(node.value)
            if isinstance(base,Symbol):
                name=base.name+'.'+node.attr
                if name in ('base64.b64decode','zlib.decompress','cryptography.fernet.Fernet'):
                    return Symbol(name)
        if isinstance(node,ast.Call) and not node.keywords:
            # Byte decoding is implemented directly on bytes, never an arbitrary method.
            if isinstance(node.func,ast.Attribute) and node.func.attr=='decode':
                value=child(node.func.value)
                args=[child(n) for n in node.args]
                if isinstance(value,bytes) and (not args or args==['utf-8']): return value.decode('utf-8')
            if isinstance(node.func,ast.Attribute) and node.func.attr=='decrypt':
                key=child(node.func.value)
                args=[child(n) for n in node.args]
                if isinstance(key,FernetKey) and len(args)==1 and isinstance(args[0],(str,bytes)):
                    from cryptography.fernet import Fernet
                    result=bounded(Fernet(key.key).decrypt(args[0]))
                    self.transforms.append({'line':node.lineno,'operation':'fernet-decrypt','input_sha256':digest(args[0]),'output_sha256':digest(result)})
                    return result
            function=child(node.func)
            args=[child(n) for n in node.args]
            if isinstance(function,Symbol) and len(args)==1:
                if function.name=='base64.b64decode' and isinstance(args[0],(str,bytes)):
                    result=bounded(base64.b64decode(args[0],validate=True))
                elif function.name=='zlib.decompress': result=unpack_zlib(args[0])
                elif function.name=='cryptography.fernet.Fernet' and isinstance(args[0],(str,bytes)):
                    return FernetKey(args[0].encode() if isinstance(args[0],str) else args[0])
                else: raise Unsupported('Function is not an allowed transform')
                self.transforms.append({'line':node.lineno,'operation':function.name,'input_sha256':digest(args[0]),'output_sha256':digest(result)})
                return result
        raise Unsupported('Unsupported expression; sample functions and eval/exec are never called')

    def process(self,tree):
        outputs=[]
        for stmt in tree.body:
            if self.steps>MAX_STEPS: break
            if isinstance(stmt,ast.Import):
                for alias in stmt.names:
                    name=alias.asname or alias.name.split('.')[0]
                    self.env.pop(name,None)
                    if alias.name in ('base64','zlib','cryptography'):
                        self.env[name]=Symbol(alias.name)
            elif isinstance(stmt,ast.ImportFrom):
                for alias in stmt.names:
                    name=alias.asname or alias.name
                    self.env.pop(name,None)
                    full=(stmt.module or '')+'.'+alias.name
                    if stmt.level==0 and full in ('base64.b64decode','zlib.decompress','cryptography.fernet.Fernet'):
                        self.env[name]=Symbol(full)
            elif isinstance(stmt,ast.Assign):
                targets=[n.id for n in stmt.targets if isinstance(n,ast.Name)]
                if len(targets)!=len(stmt.targets):
                    # Mutation through an attribute/subscript invalidates constant assumptions.
                    self.env.clear()
                    continue
                try:
                    value=self.value(stmt.value)
                except (ValueError,TypeError,SyntaxError,UnicodeError,RecursionError):
                    value=None
                for name in targets:
                    self.env.pop(name,None)
                    if value is not None: self.env[name]=value
                if isinstance(value,(str,bytes)):
                    outputs.append((stmt.lineno,value))
            elif isinstance(stmt,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                self.env.pop(stmt.name,None)
                if stmt.decorator_list: self.env.clear()
            elif isinstance(stmt,ast.Expr):
                # Inspecting literals after arbitrary calls must not assume unchanged bindings.
                # Terminal exec aliases are ignored and never invoked.
                if isinstance(stmt.value,ast.Call): self.env.clear()
            else:
                # No control-flow execution or speculative branch selection.
                self.env.clear()
        return outputs


def digest(value):
    return hashlib.sha256(value.encode('utf-8') if isinstance(value,str) else value).hexdigest()


def source_literals(record):
    """Reassemble 600-char evidence segments before considering a quoted constant."""
    joined={}
    for row in record['lines']:
        item=joined.setdefault(row.get('source_line',row['line']),{'line':row['line'],'text':''})
        item['text']+=row['text']
        bounded(item['text'])
    seen=set()
    for row in joined.values():
        text=row['text'].strip()
        match=re.match(r'^\d+\s+LOAD_CONST\s+\d+:\s*(.*)',text)
        if match: text=match.group(1)
        if not 128<=len(text)<=MAX_BYTES or not text.startswith(("'",'"',"b'",'b"')): continue
        try:
            value=ast.parse(text,mode='eval').body
            if not isinstance(value,ast.Constant) or not isinstance(value.value,(str,bytes)): continue
            blob=value.value.encode('ascii') if isinstance(value.value,str) else value.value
            if not re.fullmatch(rb'[A-Za-z0-9+/=]+',blob): continue
            raw=bounded(base64.b64decode(blob,validate=True))
            source=raw.decode('utf-8'); parse_source(source)
            sha=digest(source)
            if sha not in seen:
                seen.add(sha)
                yield source,[{'operation':'base64-constant','evidence_line':row['line'],
                               'input_sha256':digest(blob),'output_sha256':sha}]
        except (ValueError,SyntaxError,UnicodeError,RecursionError): continue


def recover(record):
    if record.get('tool') not in ('disassemble_python','decompile_python') or record.get('status')!='ok':
        raise Unsupported('Only successful Python disassembly/source evidence is accepted')
    queue=list(source_literals(record))[:8]
    if record['tool']=='decompile_python':
        joined={}
        for row in record['lines']: joined[row.get('source_line',row['line'])]=joined.get(row.get('source_line',row['line']),'')+row['text']
        queue.insert(0,('\n'.join(joined.values()),[]))
    found=[]; seen=set()
    for source,chain in queue:
        if len(found)>=8: break
        sha=digest(source)
        if sha in seen: continue
        seen.add(sha); tree=parse_source(source)
        evaluator=Constants()
        children=evaluator.process(tree)
        recovered=[]
        for line,value in children:
            if not isinstance(value,(str,bytes)) or len(value)<80: continue
            try:
                text=value.decode('utf-8') if isinstance(value,bytes) else value
                childtree=parse_source(text)
                if not any(isinstance(n,(ast.FunctionDef,ast.Import,ast.ImportFrom,ast.ClassDef)) for n in childtree.body): continue
            except (ValueError,SyntaxError,UnicodeError,RecursionError): continue
            if digest(text)!=sha and digest(text) not in seen:
                recovered.append((text,chain+evaluator.transforms+[{'operation':'source-from-assignment','source_line':line,'output_sha256':digest(text)}]))
        found.append({'source':source,'sha256':sha,'chain':chain,'has_child':bool(recovered)})
        if len(chain)<12 and len(queue)<16: queue.extend(recovered[:2])
    leaves=[r for r in found if not r['has_child']]
    if not leaves: raise Unsupported('No parseable Python payload recovered by allowed literal transforms')
    # Return bounded feature evidence, never save a runnable .py or call it.
    selected=leaves[:2]
    header={'parent_evidence_id':record['evidence_id'],'parent_output_sha256':record['output_sha256'],
            'candidates':[{k:v for k,v in r.items() if k!='source'} for r in selected],
            'scope':'candidate Python source recovered with literal transforms; no execution/reachability proof'}
    text='# STATIC DECODE PROVENANCE '+json.dumps(header,ensure_ascii=False)+'\n'
    for i,row in enumerate(selected,1): text+=f"# CANDIDATE {i} sha256={row['sha256']}\n"+row['source']+'\n'
    if len(text)>MAX_BYTES: raise Unsupported('Combined output exceeds bound')
    return text
