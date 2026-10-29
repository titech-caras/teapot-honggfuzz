"""Linux regression: python3 tools/test-gadget-fds.py HONGGFUZZ OUTPUT_DIR.

Pads inherited descriptors across both pipe endpoints and every reserved fd.
Requires a C compiler. Persistent cases inspect the channel after startup
remaps; they do not validate the persistent input state machine.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

if sys.argv[1] == '--pad':
    for _ in range(int(sys.argv[2])):
        fd = os.open('/dev/null', os.O_RDONLY)
        os.set_inheritable(fd, True)
    os.execv(sys.argv[3], sys.argv[3:])

binary = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
output.mkdir(parents=True, exist_ok=False)
target = output / 'target'
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
                str(Path(__file__).with_name('gadget-fd-target.c')), '-o', str(target)],
               check=True, timeout=30)
corpus = output / 'corpus'
corpus.mkdir()
(corpus / 'a').write_bytes(b'A')
(corpus / 'b').write_bytes(b'B')
results = []
for mode in ('fork', 'persistent'):
    # Persistent pad=1014 already fails startup on the baseline for reasons
    # outside the report pipe. Both modes cover all reserved pipe positions.
    last_pad = 1014 if mode == 'persistent' else 1015
    for pad in (0, *range(1002, last_pad)):
        work = output / f'{mode}-{pad}'
        work.mkdir()
        args = [str(binary), '-i', str(corpus), '-W', str(work),
                '-l', str(work / 'fuzzer.log'), '-n', '1', '-N', '2',
                '-r', '0', '-x', '-v']
        args += ['--linux_no_ptrace']
        if mode == 'persistent':
            args += ['-P']
        args += ['--', str(target), mode, str(work / 'fd.txt'), '___FILE___']
        with (work / 'stderr').open('wb') as err:
            process = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                      '--pad', str(pad), *args], cwd=work,
                                     stdout=subprocess.DEVNULL, stderr=err, timeout=10)
        info = (work / 'fd.txt').read_text().split() if (work / 'fd.txt').exists() else []
        files = {p.name.split('.')[2]: p.read_bytes().hex() for p in work.glob('GADGET.*')}
        valid_fd = (len(info) == 3 and info[1:] == ['0', '1'] and
                    int(info[0]) > 2 and not 1018 <= int(info[0]) <= 1023)
        saved = mode == 'persistent' or files == {'0000000000000041': '41'}
        passed = process.returncode == 0 and valid_fd and saved
        results.append(dict(mode=mode, pad=pad, fd=info, files=files, passed=passed))
(output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
failed = [f"{r['mode']}-{r['pad']}" for r in results if not r['passed']]
print(f'{len(results) - len(failed)}/{len(results)} passed; failures: {failed}')
sys.exit(bool(failed))
