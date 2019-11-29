import base64

import IPython
from IPython.terminal.ipapp import load_default_config

from base64_ import b64decode, b64encode
from random_ import LinearCongruentialRandom, HashRandom, CryptoRandom
from symmetric import OneTimePad, Feistel

context = {
    'Feistel': Feistel,
}

names = '\n'.join(f'  - {var_name}' for var_name in context)
prompt = f'''
Preset Vars:
{names}
'''
config = load_default_config()
config.TerminalInteractiveShell.banner1 = prompt
IPython.start_ipython(config=config, user_ns=context)
