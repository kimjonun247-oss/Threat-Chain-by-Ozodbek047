"""CLI-only source project registration, independent of deployment format."""
import json
from pathlib import Path
from .engine import ROOT
from . import repo_store

PROFILES=ROOT/'profiles/code'


def profiles():
    return repo_store.memo(('code_profiles',str(PROFILES)),repo_store.folder_signature(PROFILES),_profiles)


def _profiles():
    result=[]
    if PROFILES.exists():
        for path in sorted(PROFILES.glob('*.json')):
            if not repo_store.PROFILE_ID.fullmatch(path.stem):continue
            try:
                row=json.loads(path.read_text(encoding='utf-8'))
                if row['id']!=path.stem:continue
                if row.get('source')=='remote_git':result.append(row)          # no local root to compare
                elif row.get('root')==row.get('registered_root'):result.append(row)
            except (OSError,ValueError,KeyError):continue
    return result


def register_remote(target,url,ref='',name=None):
    """Register a repository that lives somewhere else.

    Only the address is stored. No credential is accepted or kept: a private
    repository works when the operator's own git credential helper or SSH agent
    already works for it, and remote_source.check_url() refuses a URL that
    carries a login precisely so one cannot end up in this file.
    """
    from . import remote_source
    if not isinstance(target,str) or not repo_store.PROFILE_ID.fullmatch(target) or target in {'crapi','crapi-full'}:
        raise ValueError('Loyiha ID 2–40 ta kichik harf, raqam, _ yoki - bo‘lsin. crapi nomlari band.')
    # The same id may name this project's Compose profile too: the portfolio
    # groups stages by id, so sharing it is the point, not a clash.
    if any(p['id']==target for p in profiles()) or (PROFILES/(target+'.json')).exists():
        raise ValueError('Bu loyiha ID allaqachon kod nishoni sifatida mavjud.')
    url=remote_source.check_url(url)
    ref=remote_source.check_ref(ref)
    if not isinstance(name or target,str) or len(name or target)>120:raise ValueError('Loyiha nomi juda uzun.')
    row={'id':target,'name':name or target,'source':'remote_git','url':url,'ref':ref,
         'note':'Har bir skan uchun vaqtinchalik sayoz nusxa olinadi va skandan keyin o‘chiriladi.'}
    PROFILES.mkdir(parents=True,exist_ok=True)
    with (PROFILES/(target+'.json')).open('x',encoding='utf-8') as file:json.dump(row,file,ensure_ascii=False,indent=2)
    return {'id':target,'name':row['name'],'source':'remote_git','url':url,'ref':ref}


def register(target,root,name=None):
    if not isinstance(target,str) or not repo_store.PROFILE_ID.fullmatch(target) or target in {'crapi','crapi-full'}:
        raise ValueError('Loyiha ID 2–40 ta kichik harf, raqam, _ yoki - bo‘lsin. crapi nomlari band.')
    # The same id may name this project's Compose profile too: the portfolio
    # groups stages by id, so sharing it is the point, not a clash.
    if any(p['id']==target for p in profiles()) or (PROFILES/(target+'.json')).exists():
        raise ValueError('Bu loyiha ID allaqachon kod nishoni sifatida mavjud.')
    source=Path(root).resolve()
    if not source.is_dir():raise ValueError('Loyiha papkasi mavjud emas.')
    if not isinstance(name or target,str) or len(name or target)>120:raise ValueError('Loyiha nomi juda uzun.')
    row={'id':target,'name':name or target,'root':str(source),'registered_root':str(source)}
    PROFILES.mkdir(parents=True,exist_ok=True)
    with (PROFILES/(target+'.json')).open('x',encoding='utf-8') as file:json.dump(row,file,ensure_ascii=False,indent=2)
    return {'id':target,'name':row['name']}


def remove(target):
    """Drop a local or remote source registration. Reports stay in the history,
    and the project's folder is never touched."""
    path=PROFILES/(str(target)+'.json')
    if not repo_store.PROFILE_ID.fullmatch(str(target)) or not path.is_file():
        raise ValueError('Bunday ro‘yxatdagi kod loyihasi yo‘q.')
    path.unlink()
    return {'id':target,'removed':True,'note':'Manba papkasiga tegilmadi; oldingi hisobotlar tarixda qoldi.'}
