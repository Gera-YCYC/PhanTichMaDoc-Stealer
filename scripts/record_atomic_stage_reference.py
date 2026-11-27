"""Reproduce the explicitly source-audited DEVELOPMENT reference, not model labels.

The rows below were checked against decoded-source coordinates and the earlier
13-unit source audit. They are not generated from model statements or fact IDs.
No human or lecturer review is asserted. This profile is not a blind test set.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EID = 'ev_c862ffaf2b5f4de5'
SOURCE_HASH = 'f2d6246d769fe363ca08bafef3cbe5217e2e8f5ed05561faa842f61ea0e17100'
ROWS = [
    ('A01', 'behavior', 'Reads the browser Local State file.', [(52,61)]),
    ('A02', 'behavior', 'Base64-decodes the os_crypt.encrypted_key value from Local State.', [(61,64)]),
    ('A03', 'behavior', 'Passes the key bytes after removing the five-byte prefix to CryptUnprotectData.', [(11,11),(63,66)]),
    ('A04', 'behavior', 'Calls AES-GCM decrypt on payload with master_key and iv expressions.', [(12,12),(69,75)]),
    ('A05', 'behavior', 'Copies the browser Login Data file to a temporary login_db path.', [(10,10),(134,139)]),
    ('A06', 'behavior', 'Opens SQLite using the temporary login_db path expression.', [(9,9),(140,140)]),
    ('A07', 'behavior', 'Executes SELECT action_url, username_value, password_value FROM logins.', [(9,9),(140,142)]),
    ('A08', 'behavior', 'Fetches rows of the login SELECT with cursor.fetchall.', [(140,143)]),
    ('A09', 'behavior', 'Passes the selected password_value field to the local AES-GCM helper.', [(12,12),(69,75),(140,144)]),
    ('A10', 'behavior', 'Copies the browser Web Data file to a temporary cards_db path.', [(10,10),(157,163)]),
    ('A11', 'behavior', 'Opens SQLite using the temporary cards_db path expression.', [(9,9),(164,164)]),
    ('A12', 'behavior', 'Executes the credit_cards SELECT for stored name, expiration, encrypted card number and modification fields.', [(9,9),(164,167)]),
    ('A13', 'behavior', 'Fetches rows of the credit_cards SELECT with cursor.fetchall.', [(164,168)]),
    ('A14', 'behavior', 'Passes the selected card_number_encrypted field to the local AES-GCM helper.', [(12,12),(69,75),(164,172)]),
    ('A15', 'behavior', 'Writes non-null content into a text file under the temporary Browser directory.', [(116,124)]),
    ('A16', 'behavior', 'Passes login_data to save_results for writing Saved_Passwords output.', [(116,124),(299,299),(308,308)]),
    ('A17', 'behavior', 'Passes credit_cards_data to save_results for writing Saved_Credit_Cards output.', [(116,124),(300,300),(309,309)]),
    ('A18', 'behavior', 'Calls shutil.make_archive with zip format and the temporary Browser directory expression.', [(10,10),(276,279)]),
    ('A19', 'behavior', 'Reads attachment_path bytes into a MIME part payload.', [(96,98)]),
    ('A20', 'behavior', 'Attaches the MIME part to the multipart email message.', [(90,90),(96,102)]),
    ('A21', 'behavior', 'Serializes the multipart email message using as_string.', [(90,90),(102,103)]),
    ('A22', 'behavior', 'Constructs an SMTP connection using the configured server and port.', [(14,14),(83,84),(106,106)]),
    ('A23', 'behavior', 'Requests STARTTLS on the SMTP connection.', [(14,14),(106,107)]),
    ('A24', 'behavior', 'Calls SMTP login with the configured username and password expressions.', [(14,14),(106,108)]),
    ('A25', 'behavior', 'Calls SMTP sendmail with from_email, to_email and text expressions.', [(14,14),(106,106),(109,109)]),
    ('A26', 'behavior', 'Passes the archive-helper return path to the email helper attachment parameter.', [(82,82),(96,103),(276,286),(315,315),(323,323)]),
    ('A27', 'ioc', 'Configured SMTP destination hostname is mail.dasmake.xyz; static destination, not observed traffic.', [(83,84),(106,106)]),
    ('A28', 'attack', 'T1555.003: browser credential access supported by Login Data copy/query and key/decryption code.', [(52,75),(134,154)]),
    ('A29', 'attack', 'T1560.002: archive collected data via shutil.make_archive on the staging directory.', [(116,124),(276,286),(308,315)]),
]


def main():
    prior = ROOT / 'eval/reference_units/python2024.behavior-v1.json'
    profile = {'schema_version': 1, 'profile_id': 'python2024.atomic-development/1',
        'sample_sha256': '7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db',
        'scope': 'Declared browser-password/card collection, archive and SMTP chain in a decoded development payload; not every behavior in the binary.',
        'reference_method': 'Explicit source audit; atomic decomposition of the earlier 13-unit reference with source-level operations and IOC/ATTACK units.',
        'source_references': [{'path': prior.relative_to(ROOT).as_posix(), 'sha256': hashlib.sha256(prior.read_bytes()).hexdigest()},
            {'evidence_id': EID, 'parser_source_sha256': SOURCE_HASH},
            'https://docs.python.org/3/library/sqlite3.html', 'https://docs.python.org/3/library/smtplib.html',
            'https://attack.mitre.org/techniques/T1555/003/', 'https://attack.mitre.org/techniques/T1560/002/'],
        'scoring_ready': True, 'model_self_review_used_as_truth': False, 'human_reviewers': [],
        'dataset_split': 'development', 'reference_created_after_development_runs': True,
        'reference_design_used_development_error_analysis': True,
        'unit_policy': 'One source operation with its operand roles at the specified source site, or one typed IOC/ATTACK assertion. '
                       'Repeated paraphrases of that assertion receive one unit of credit. A generic call does not satisfy a dataflow or helper-effect unit.',
        'not_covered': ['Other browser history/download/autofill behavior', 'Whole-module reachability',
                        'Runtime execution', 'Credential literal publication', 'Whole-corpus/whole-course acceptance'],
        'units': [{'id': 'PY24-' + ident, 'kind': kind, 'proposition': text,
                   'source_references': [{'evidence_id': EID, 'line': lo, 'end_line': hi} for lo,hi in spans]}
                  for ident,kind,text,spans in ROWS]}
    dest = ROOT / 'eval/reference_units/python2024.atomic-v1.json'
    dest.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'path': str(dest.relative_to(ROOT)), 'units': len(profile['units']), 'dataset': 'development'}))


if __name__ == '__main__':
    main()
