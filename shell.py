import base64

import IPython
from IPython.terminal.ipapp import load_default_config

from aes import AES
from base64_ import b64decode, b64encode
from rsa import Mod12, RSAPrivateKey, RSAPublicKey

context = {
    'AES': AES,
    'Mod12': Mod12,
    'RSAPrivateKey': RSAPrivateKey,
    'RSAPublicKey': RSAPublicKey,
    'b64decode': b64decode,
    'b64encode': b64encode,
    'base64': base64,
    'bin_': lambda number: format(number, '08b'),
}

names = '\n'.join(f'  - {var_name}' for var_name in context)
prompt = f'''
Preset Vars:
{names}
'''
config = load_default_config()
config.TerminalInteractiveShell.banner1 = prompt
IPython.start_ipython(config=config, user_ns=context)
