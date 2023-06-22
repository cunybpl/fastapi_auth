import toml 
import os
import sys
import logging 
l = logging.getLogger(__name__)

if __name__ == '__main__': 

    rootdir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))    
    
    try:
        proj = toml.load(os.path.join(rootdir, 'pyproject.toml')) 
    except IOError as err:
        l.error(err)
        sys.exit(1)

    try:
        num = proj['tool']['poetry']['version']
        print(f"VERSION_TAG={num}")
    except KeyError as err:
        l.error(err)
        sys.exit(2)