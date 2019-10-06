import base64

import IPython
from IPython.terminal.ipapp import load_default_config

from util import b64decode, b64encode

context = {
    'base64': base64,
    'b64decode': b64decode,
    'b64encode': b64encode,
}

names = '\n'.join(f'  - {var_name}' for var_name in context)
prompt = f'''
Preset Vars:
{names}
'''
config = load_default_config()
config.TerminalInteractiveShell.banner1 = prompt
IPython.start_ipython(config=config, user_ns=context)
