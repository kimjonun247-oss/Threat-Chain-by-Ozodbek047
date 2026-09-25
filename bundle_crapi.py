"""Copy the local demo source without deleting or replacing existing files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

from zanjir.engine import ROOT


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def checked_path(path, root):
    """Reject links/junctions in every traversed component, including broken links."""
    relative = path.relative_to(root)
    for candidate in (root, *(root / Path(*relative.parts[:i]) for i in range(1, len(relative.parts) + 1))):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError('Link/junction orqali nusxa olinmaydi: ' + str(candidate))
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Nusxa yo‘li belgilangan papkadan tashqarida.')


def walk_error(error):
    raise error


def bundle(source, app_root=ROOT):
    source = Path(source).absolute()
    app_root = Path(app_root).absolute()
    target = app_root / 'work/repositories/crapi-stable'
    checked_path(source, source)
    checked_path(target, app_root)
    if not source.is_dir():
        raise ValueError('crAPI manba papkasi topilmadi: ' + str(source))
    if source.resolve().is_relative_to(target.resolve()) or target.resolve().is_relative_to(source.resolve()):
        raise ValueError('Manba va manzil bir-birining ichida bo‘lmasligi kerak.')
    entries = []
    for folder, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(name for name in dirs if name not in {'.git', '.github'})
        for name in dirs + sorted(files):
            item = Path(folder) / name
            checked_path(item, source)
            checked_path(target / item.relative_to(source), app_root)
        for name in sorted(files):
            src = Path(folder) / name
            if not stat.S_ISREG(src.stat().st_mode):
                raise ValueError('Faqat oddiy fayllar nusxalanadi: ' + str(src))
            relative = src.relative_to(source)
            dest = target / relative
            checksum = digest(src)
            if dest.exists() and (not dest.is_file() or digest(dest) != checksum):
                raise ValueError('Manzilda o‘zgartirilgan fayl bor; ustiga yozilmadi: ' + relative.as_posix())
            entries.append((src, dest, relative.as_posix(), checksum))
    if not entries:
        raise ValueError('Manbada nusxalanadigan fayl yo‘q.')
    # Complete preflight before any write. Exclusive creation also prevents overwrites.
    copied = 0
    for src, dest, _, checksum in entries:
        checked_path(dest, app_root)
        if dest.exists():
            if digest(dest) != checksum:
                raise ValueError('Manzil nusxa olish vaqtida o‘zgargan; ustiga yozilmadi.')
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with src.open('rb') as incoming, dest.open('xb') as outgoing:
            shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
        if digest(dest) != checksum:
            raise ValueError('Manba nusxa olish vaqtida o‘zgargan. Nusxani tekshiring.')
        copied += 1
    inventory = sorted((relative, checksum) for _, _, relative, checksum in entries)
    return {'copied': copied, 'unchanged': len(entries) - copied, 'files': len(entries),
            'inventory_sha256': hashlib.sha256(json.dumps(inventory).encode()).hexdigest(),
            'target': str(target), 'policy': 'No deletion or replacement; .git and .github excluded'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT.parents[1] / 'work/repositories/crapi-stable')
    args = parser.parse_args()
    try:
        print(json.dumps(bundle(args.source), ensure_ascii=False, indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
