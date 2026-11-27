"""Bounded Python API bindings for collection, staging and transport; never import code."""
import ast
from collections import Counter


def candidates(source):
    text = source.decode('utf-8')
    tree = ast.parse(text)
    nodes = []
    for node in ast.walk(tree):
        nodes.append(node)
        if len(nodes) > 200_000:
            raise ValueError('AST node limit')
    parents = {child:node for node in nodes for child in ast.iter_child_nodes(node)}
    if any(isinstance(n,ast.ImportFrom) and any(a.name=='*' for a in n.names) for n in nodes):
        return []  # A wildcard can replace every apparent builtin/import binding.

    def owner(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef,ast.AsyncFunctionDef,ast.Lambda)):
                return node
        return tree

    def ancestors(node):
        result = set()
        while node in parents:
            node = parents[node]
            result.add(node)
        return result

    def span(node):
        return node.lineno, node.end_lineno

    def expr(node):
        value = ast.get_source_segment(text, node)
        return value if value is not None and len(value) <= 240 else None

    imports = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {'sqlite3','smtplib','shutil','base64','win32crypt'}:
                    imports[alias.asname or alias.name] = (alias.name, node)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            allowed = {'Crypto.Cipher': {'AES'}, 'Cryptodome.Cipher': {'AES'},
                       'win32crypt': {'CryptUnprotectData'}, 'email': {'encoders'},
                       'email.mime.base': {'MIMEBase'}, 'email.mime.multipart': {'MIMEMultipart'},
                       'email.mime.text': {'MIMEText'}}
            for alias in node.names:
                if alias.name in allowed.get(node.module, set()):
                    imports[alias.asname or alias.name] = (node.module+'.'+alias.name, node)
    imported_names = Counter()
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                imported_names[alias.asname or alias.name.split('.')[0]] += 1
    rebound = {n.id for n in nodes if isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del))}
    rebound.update(name for name,count in imported_names.items() if count > 1)
    rebound.update(n.arg for n in nodes if isinstance(n,ast.arg))
    rebound.update(n.name for n in nodes if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)))
    rebound.update(n.value.id for n in nodes if isinstance(n,ast.Attribute) and
                   isinstance(n.ctx,(ast.Store,ast.Del)) and isinstance(n.value,ast.Name))
    for node in nodes:
        if isinstance(node,ast.Assign) and isinstance(node.value,ast.Name) and node.value.id in imports:
            # Escaped module/function aliases can be mutated through another name.
            rebound.add(node.value.id)
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'setattr','delattr'} and node.args and isinstance(node.args[0],ast.Name):
            rebound.add(node.args[0].id)
    imports = {k:v for k,v in imports.items() if k not in rebound}
    stores = [n for n in nodes if isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del))]
    definitions = []
    for node in nodes:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            definitions.append((node.targets[0],node.value,node,parents[node]))
        elif isinstance(node,(ast.With,ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.optional_vars,ast.Name):
                    definitions.append((item.optional_vars,item.context_expr,node,node))

    def direct(call):
        fn = call.func
        if isinstance(fn,ast.Name) and fn.id in imports:
            return imports[fn.id]
        if isinstance(fn,ast.Name) and fn.id=='open' and not {'open','builtins'} & (rebound | set(imported_names)):
            return 'builtins.open',None
        if isinstance(fn,ast.Attribute) and isinstance(fn.value,ast.Name) and fn.value.id in imports:
            module, imported = imports[fn.value.id]
            return module+'.'+fn.attr, imported
        return None,None

    def open_info(call):
        if direct(call)[0] != 'builtins.open' or not 1 <= len(call.args) <= 2:
            return None
        if any(isinstance(n,ast.Starred) for n in call.args) or any(k.arg not in {'encoding','errors'} for k in call.keywords):
            return None
        mode = call.args[1].value if len(call.args)==2 and isinstance(call.args[1],ast.Constant) else ('r' if len(call.args)==1 else None)
        if mode not in {'r','rb','w','wb','a','ab'} or expr(call.args[0]) is None:
            return None
        if any(not isinstance(k.value,ast.Constant) or not isinstance(k.value.value,str) for k in call.keywords):
            return None
        if 'b' in mode and call.keywords:
            return None
        return {'path_expression':expr(call.args[0]), 'mode':mode}

    def instance(name, call, depth=0):
        if depth > 3:
            return None,[]
        matches = [d for d in definitions if d[0].id==name and owner(d[0])==owner(call)]
        if len(matches)!=1:
            return None,[]
        target,value,statement,block = matches[0]
        if target.lineno > call.lineno or block not in ancestors(call):
            return None,[]
        # Any second store in the same function, including loops/augassign, invalidates the binding.
        if any(n.id==name and n is not target and owner(n)==owner(call) for n in stores):
            return None,[]
        if any(owner(n)==owner(call) and isinstance(n,ast.Attribute) and
               isinstance(n.ctx,(ast.Store,ast.Del)) and isinstance(n.value,ast.Name) and n.value.id==name
               for n in nodes):
            return None,[]
        if any(owner(n)==owner(call) and isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and
               n.func.id in {'setattr','delattr'} and n.args and isinstance(n.args[0],ast.Name) and n.args[0].id==name
               for n in nodes):
            return None,[]
        if not isinstance(value,ast.Call):
            return None,[]
        opened = open_info(value)
        if opened:
            return 'file:'+opened['mode'],[span(value)]
        if value.keywords or any(isinstance(a,ast.Starred) for a in value.args):
            return None,[]
        api, imported = direct(value)
        ranges = [span(imported),span(statement)] if imported else []
        # With statements can span the whole function; the constructor itself is enough.
        if isinstance(statement,(ast.With,ast.AsyncWith)) and imported:
            ranges = [span(imported),span(value)]
        if api=='sqlite3.connect':
            return 'sqlite_connection',ranges
        if api in {'smtplib.SMTP','smtplib.SMTP_SSL'}:
            return 'smtp',ranges
        if api=='email.mime.multipart.MIMEMultipart' and not value.args:
            return 'mime_multipart',ranges
        if api=='email.mime.base.MIMEBase' and len(value.args)==2:
            return 'mime_part',ranges
        if api in {'Crypto.Cipher.AES.new','Cryptodome.Cipher.AES.new'} and len(value.args)==3:
            mode = value.args[1]
            if isinstance(mode,ast.Attribute) and isinstance(mode.value,ast.Name) and mode.attr=='MODE_GCM' and mode.value.id==value.func.value.id:
                return 'aes_gcm_cipher',ranges
        if isinstance(value.func,ast.Attribute) and value.func.attr=='cursor' and isinstance(value.func.value,ast.Name):
            parent_type,parent_ranges = instance(value.func.value.id,value,depth+1)
            if parent_type=='sqlite_connection':
                return 'sqlite_cursor', [*parent_ranges,span(statement)]
        return None,[]

    def result_name(call):
        parent = parents.get(call)
        if isinstance(parent,ast.Assign) and len(parent.targets)==1 and isinstance(parent.targets[0],ast.Name):
            return parent.targets[0].id
        return None

    results, last_queries = [], {}
    for call in sorted((n for n in nodes if isinstance(n,ast.Call)),key=lambda n:(n.lineno,n.col_offset)):
        if isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.attr in {'execute','executemany','executescript','close'}:
            # An unsupported call can still replace a cursor's result set.
            last_queries.pop((id(owner(call)),call.func.value.id),None)
        # Only positional forms have a verified argument-role mapping in this version.
        if call.keywords or any(isinstance(a,ast.Starred) for a in call.args):
            continue
        args = [expr(n) for n in call.args]
        if any(a is None for a in args):
            continue
        api, imported = direct(call)
        operation, inputs, meaning, ranges = None,{},None,[]
        if api=='sqlite3.connect' and len(args)==1:
            operation,inputs,meaning = 'database_open',{'path_expression':args[0]},'sqlite_connection'
            ranges = [span(imported),span(call)]
        elif api=='shutil.make_archive' and 2 <= len(args) <= 4:
            operation,inputs,meaning = 'archive_create',{'base_name_expression':args[0], 'format_expression':args[1],
                'root_directory_expression':args[2] if len(args)>2 else None},'archive_path'
            ranges = [span(imported),span(call)]
        elif api in {'shutil.copy','shutil.copy2'} and len(args)==2:
            operation,inputs,meaning = 'file_copy',{'source_path_expression':args[0], 'destination_path_expression':args[1]},'destination_path'
            ranges = [span(imported),span(call)]
        elif api=='base64.b64decode' and len(args)==1:
            operation,inputs,meaning = 'base64_decode',{'encoded_data_expression':args[0]},'decoded_bytes_not_cryptographic_decryption'
            ranges = [span(imported),span(call)]
        elif api=='win32crypt.CryptUnprotectData' and 1 <= len(args) <= 5:
            operation,inputs,meaning = 'dpapi_unprotect',{'protected_data_expression':args[0]},'description_and_unprotected_bytes_tuple'
            ranges = [span(imported),span(call)]
        elif api in {'smtplib.SMTP','smtplib.SMTP_SSL'} and 1 <= len(args) <= 2:
            operation,inputs,meaning = 'smtp_connect',{'host_expression':args[0], 'port_expression':args[1] if len(args)>1 else None},'smtp_client_not_message_delivery'
            ranges = [span(imported),span(call)]
        elif api=='email.encoders.encode_base64' and len(args)==1:
            operation,inputs,meaning = 'mime_base64_encode',{'part_expression':args[0]},'mime_content_transfer_encoding_not_encryption'
            ranges = [span(imported),span(call)]
        elif isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name):
            kind, ranges = instance(call.func.value.id,call)
            method = call.func.attr
            receiver_key = (id(owner(call)),call.func.value.id)
            if kind in {'sqlite_connection','sqlite_cursor'} and method=='execute' and len(args)==1 and isinstance(call.args[0],ast.Constant) and isinstance(call.args[0].value,str) and call.args[0].value.lstrip().upper().startswith('SELECT '):
                operation,api,inputs,meaning = 'sql_select','sqlite3.execute',{'query_expression':args[0]},'sqlite_cursor_for_query_not_fetched_or_decrypted_values'
                last_queries[receiver_key] = (call,args[0])
            elif kind=='sqlite_cursor' and method=='fetchall' and not args and receiver_key in last_queries:
                query,expression = last_queries[receiver_key]
                # Statement block must dominate the fetch, not a conditional sibling.
                query_statement = parents.get(query)
                if query_statement is not None and parents.get(query_statement) in ancestors(call):
                    operation,api,inputs,meaning = 'sql_fetchall','sqlite3.Cursor.fetchall',{'query_expression':expression},'remaining_rows_not_decrypted_values'
                    ranges = [*ranges,span(query)]
            elif kind=='smtp' and method=='sendmail' and len(args)==3:
                operation,api,inputs,meaning = 'smtp_send','smtplib.SMTP.sendmail',{'sender_expression':args[0],
                    'recipient_expression':args[1],'message_expression':args[2]},'recipient_refusal_mapping_not_message_bytes'
            elif kind=='smtp' and method=='starttls' and not args:
                operation,api,inputs,meaning = 'smtp_starttls','smtplib.SMTP.starttls',{'client_expression':call.func.value.id},'starttls_request_not_observed_tls_success'
            elif kind=='smtp' and method=='login' and len(args)==2:
                operation,api,inputs,meaning = 'smtp_login','smtplib.SMTP.login',{'username_expression':args[0], 'password_expression':args[1]},'authentication_attempt_not_observed_success'
            elif kind in {'mime_part','mime_multipart'} and method=='set_payload' and len(args)==1:
                operation,api,inputs,meaning = 'mime_set_payload','email.message.Message.set_payload',{'part_expression':call.func.value.id, 'payload_expression':args[0]},'payload_assignment_not_network_send'
            elif kind=='mime_multipart' and method=='attach' and len(args)==1:
                operation,api,inputs,meaning = 'mime_attach','email.message.Message.attach',{'message_expression':call.func.value.id, 'part_expression':args[0]},'append_payload_not_network_send'
            elif kind in {'mime_part','mime_multipart'} and method=='as_string' and not args:
                operation,api,inputs,meaning = 'mime_serialize','email.message.Message.as_string',{'message_expression':call.func.value.id},'message_text_not_network_send'
            elif kind and kind.startswith('file:'):
                constructor = next(d[1] for d in definitions if d[0].id==call.func.value.id and owner(d[0])==owner(call))
                info = open_info(constructor)
                api_base = 'io.BufferedIOBase' if 'b' in info['mode'] else 'io.TextIOBase'
                if method=='read' and not args and info['mode'].startswith('r'):
                    operation,api,inputs,meaning = 'file_read',api_base+'.read',{'path_expression':info['path_expression']},'file_contents_without_data_type_inference'
                elif method=='write' and len(args)==1 and info['mode'].startswith(('w','a')):
                    operation,api,inputs,meaning = 'file_write',api_base+'.write',{'path_expression':info['path_expression'], 'data_expression':args[0]},'written_count_not_sensitive_content_proof'
            elif kind=='aes_gcm_cipher' and method=='decrypt' and len(args)==1:
                constructor = next(d[1] for d in definitions if d[0].id==call.func.value.id and owner(d[0])==owner(call))
                key, nonce = expr(constructor.args[0]), expr(constructor.args[2])
                if key is not None and nonce is not None:
                    operation,api,inputs,meaning = 'aes_gcm_decrypt','PyCryptodome.AES.GCM.decrypt',{
                        'ciphertext_expression':args[0],'key_expression':key,'nonce_expression':nonce},'plaintext_bytes_not_authentication_or_text_decoding'
            if operation:
                ranges = [*ranges,span(call)]
        elif isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Call) and call.func.attr=='read' and not args:
            info = open_info(call.func.value)
            if info and info['mode'].startswith('r'):
                operation,api,inputs,meaning = 'file_read',('io.BufferedIOBase' if 'b' in info['mode'] else 'io.TextIOBase')+'.read',{'path_expression':info['path_expression']},'file_contents_without_data_type_inference'
                ranges = [span(call.func.value),span(call)]
        if operation:
            results.append({'operation':operation,'api':api,'inputs':inputs,
                            'result':{'meaning':meaning,'assigned_expression':result_name(call)},
                            'binding':'direct_import_or_unique_visible_instance_no_reassignment',
                            'source_ranges':ranges})
    return results
