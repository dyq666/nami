import IPython
from IPython.terminal.ipapp import load_default_config

from util import b64encode

context = {
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
