"""Explicit maintainer command: push a prepared commit and verified Release assets.

Never called by installation or demo. Requires Write and a clean reviewed repository.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT if (ROOT/'.git').is_dir() else ROOT/'private/group-delivery-repo'


def run(args,**kw):
    return subprocess.check_output(args,text=True,encoding='utf-8',**kw).strip()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--publish',action='store_true',help='Explicitly perform remote writes')
    args=parser.parse_args()
    lock=json.loads((ROOT/'config/release-assets.lock.json').read_text())
    remote=lock['repository']
    origin=run(['git','remote','get-url','origin'],cwd=REPO)
    if origin.removesuffix('.git')!='https://github.com/'+remote:
        raise SystemExit('Configured Release repository and Git origin differ; no remote writes')
    permission=json.loads(run(['gh','repo','view',remote,'--json','viewerPermission']))['viewerPermission']
    if permission not in ('WRITE','MAINTAIN','ADMIN'):
        raise SystemExit('No remote write: current GitHub permission is '+permission)
    if run(['git','status','--porcelain'],cwd=REPO):
        raise SystemExit('Commit/review source changes before publishing')
    head=run(['git','rev-parse','HEAD'],cwd=REPO)
    subprocess.run(['git','fetch','origin','main'],cwd=REPO,check=True)
    subprocess.run(['git','merge-base','--is-ancestor','origin/main','HEAD'],cwd=REPO,check=True)
    paths=[]
    for record in lock['assets']:
        file=ROOT/'private/release-assets'/record['file']
        with file.open('rb') as stream:
            digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if digest!=record['sha256'] or file.stat().st_size!=record['bytes']:
            raise ValueError('Release asset differs: '+file.name)
        paths.append(str(file))
    if not args.publish:
        print(json.dumps({'ready_commit':head,'permission':permission,'assets':len(paths),'remote_write':False}))
        return
    # Normal fast-forward push only; preserve the selected repository's history.
    subprocess.run(['git','push','origin','HEAD:main'],cwd=REPO,check=True)
    if run(['git','ls-remote','origin','refs/heads/main'],cwd=REPO).split()[0]!=head:
        raise RuntimeError('Remote main did not match pushed commit')
    tag=lock['tag']
    existing=subprocess.run(['gh','release','view',tag,'--repo',remote,'--json','isDraft,targetCommitish'],capture_output=True,text=True,encoding='utf-8')
    if existing.returncode==0:
        if not json.loads(existing.stdout)['isDraft']:
            raise RuntimeError('Release already public; no silent replacement')
        if json.loads(existing.stdout)['targetCommitish'] != head:
            if run(['git','ls-remote','origin','refs/tags/'+tag],cwd=REPO):
                raise RuntimeError('Existing tag has another target; no silent retagging')
            subprocess.run(['gh','release','edit',tag,'--repo',remote,'--target',head],check=True)
    else:
        subprocess.run(['gh','release','create',tag,'--repo',remote,'--target',head,'--draft',
                        '--title','Tài nguyên chạy lab: model cục bộ và mẫu nghiên cứu',
                        '--notes-file',str(ROOT/'docs/RELEASE_NOTES.md')],check=True)
    release_id=json.loads(run(['gh','release','view',tag,'--repo',remote,'--json','databaseId']))['databaseId']
    # The REST tag endpoint only returns published releases; drafts need an ID.
    release_api=f'repos/{remote}/releases/{release_id}'
    pending=[]
    metadata=json.loads(run(['gh','api',release_api]))
    for file,record in zip(paths,lock['assets']):
        prior=next((a for a in metadata['assets'] if a['name']==record['file']),None)
        if prior:
            if prior.get('digest')=='sha256:'+record['sha256'] and prior['size']==record['bytes'] and prior['state']=='uploaded':
                print('Already verified remote asset: '+record['file'],flush=True)
                continue
            raise RuntimeError('Existing remote asset differs; no silent replacement: '+record['file'])
        pending.append(file)
        print('Pending upload '+record['file']+' ('+str(record['bytes'])+' bytes)',flush=True)
    if pending:
        # gh uploads distinct files concurrently (bounded by its own worker pool).
        # Previously verified assets are preserved; --clobber is never used.
        subprocess.run(['gh','release','upload',tag,'--repo',remote,*pending],check=True)
    metadata=json.loads(run(['gh','api',release_api]))
    assets={a['name']:a for a in metadata['assets']}
    for expected in lock['assets']:
        actual=assets.get(expected['file'])
        if (not actual or actual['size']!=expected['bytes'] or
            actual.get('digest')!='sha256:'+expected['sha256'] or actual.get('state')!='uploaded'):
            raise RuntimeError('Remote asset verification failed; leave draft for inspection')
    subprocess.run(['gh','release','edit',tag,'--repo',remote,'--draft=false'],check=True)
    metadata=json.loads(run(['gh','api',release_api]))
    if metadata['draft']:
        raise RuntimeError('GitHub still reports a draft release')
    receipt={'commit':head,'release_url':metadata['html_url'],'assets':len(assets),
             'remote_sizes_and_sha256_verified':True,'source_push_verified':True}
    out=ROOT/'evidence/local/publish-receipt.json'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(receipt,indent=2))
    print(json.dumps(receipt))


if __name__=='__main__':
    main()
