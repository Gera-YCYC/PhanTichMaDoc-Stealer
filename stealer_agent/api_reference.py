"""Small offline API reference for grounded reporting, never sample evidence.

Literal matching selects reference notes only. It does not establish a call, type
binding, reachability or behavior; source citations must establish those facts.
"""
from __future__ import annotations

import hashlib
import json

REFERENCE_VERSION = 'static-api-reference/2'
REFERENCES = (
    {'id': 'dotnet.webclient.uploadfile', 'needles': ('UploadFile',),
     'semantics': 'System.Net.WebClient.UploadFile(address, fileName) sends the local file named by fileName; '
                  'the second argument is a FILE PATH, not bytes or a password value. The returned byte[] is the '
                  'RESPONSE BODY. A suggestive variable name does not prove file contents.',
     'source': 'https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.uploadfile?view=net-10.0'},
    {'id': 'dotnet.encoding.getstring', 'needles': ('GetString',),
     'semantics': 'Encoding.ASCII.GetString(bytes) decodes character encoding into text. It is NOT cryptographic '
                  'decryption. If bytes came from UploadFile, the text is the response, not the uploaded file.',
     'source': 'https://learn.microsoft.com/en-us/dotnet/api/system.text.asciiencoding.getstring?view=net-10.0'},
    {'id': 'dotnet.latebinding', 'needles': ('LateGet',),
     'semantics': 'NewLateBinding.LateGet(instance, type, memberName, arguments, ...) dispatches the selected '
                  'member on the supplied instance. A new WebClient plus literal member UploadFile and an '
                  'address/file-path argument array is an indirect UploadFile call. Check instance and arguments; '
                  'a member-name string alone is insufficient.',
     'source': 'https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.compilerservices.newlatebinding.lateget?view=net-10.0'},
    {'id': 'python.sqlite3', 'needles': ('sqlite3', 'SELECT ', 'select '),
     'semantics': 'sqlite3.connect(path) opens a database connection. Cursor.execute(SELECT ...) and fetchall '
                  'retrieve selected stored fields. A SELECT of password_value or card_number_encrypted does '
                  'not decrypt those fields. A later custom helper call needs its implementation to prove decryption.',
     'source': 'https://docs.python.org/3/library/sqlite3.html'},
    {'id': 'python.smtp', 'needles': ('smtplib', '.sendmail(', '.starttls('),
     'semantics': 'SMTP(host, port) creates a connection when host is set. login authenticates; sendmail '
                  'submits the message. Mere host/port assignments are not a connection or send. To claim an '
                  'attachment, require payload construction plus message attachment and the send call, not a filename alone.',
     'source': 'https://docs.python.org/3/library/smtplib.html'},
    {'id':'python.fileio', 'needles':('shutil.copy','open(','.write(','.read('),
     'semantics':'open(path, mode) creates a file object; read returns its contents, write receives data. '
                 'shutil.copy(src,dst) copies a file to a destination path. A path variable is not its contents; '
                 'custom wrappers require their body and argument binding before claiming the same effect.',
     'source':'https://docs.python.org/3/library/shutil.html'},
    {'id':'python.mime','needles':('MIMEMultipart','MIMEBase','set_payload','as_string','msg.attach'),
     'semantics':'set_payload stores a MIME payload; attach appends a part; as_string serializes the message. '
                 'Content-transfer Base64 is not cryptographic encryption. Follow the read, payload and attach '
                 'values before asserting which file a sent message contains.',
     'source':'https://docs.python.org/3/library/email.mime.html'},
    {'id':'python.dpapi','needles':('CryptUnprotectData',),
     'semantics':'win32crypt.CryptUnprotectData returns (description, unprotected bytes). Selecting [1] takes the bytes. '
                 'Prove the imported binding; a declaration or helper name alone proves neither a call nor decrypted passwords.',
     'source':'https://timgolden.me.uk/pywin32-docs/win32crypt__CryptUnprotectData_meth.html'},
)


def reference_for(text):
    """Return only fixed trusted strings; sample text never enters this context."""
    selected = [row for row in REFERENCES if any(n in text for n in row['needles'])]
    notes = [{k: row[k] for k in ('id', 'semantics', 'source')} for row in selected]
    return {'version': REFERENCE_VERSION, 'entries': notes,
            'sha256': hashlib.sha256(json.dumps(notes, sort_keys=True).encode()).hexdigest()}


def reference_prompt(pack):
    if not pack['entries']:
        return ''
    return ('\nTrusted API reference (not sample evidence; apply only when source proves the API binding):\n' +
            '\n'.join(row['id'] + ': ' + row['semantics'] for row in pack['entries']))
