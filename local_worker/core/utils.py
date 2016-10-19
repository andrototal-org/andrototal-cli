"""
this module contains some utility functions for the command line tool
"""

import os, sys
import re
import argparse
from contextlib import contextmanager
import io
import hashlib

# import needed to let python find the module
# when importing adapters (is it a bug in __import__?)
from adapters import *
from virtualdevice import AVD

ADAPTERS_PACKAGE = 'adapters'
DEVICES_DATA_DIR = 'devices_data'

def pick_unused_port():
    """
    Open and close a random socket returning its port number.
    Note that calling this method does not guarantee the port
    will actually be free when used.

    TODO: implement a global lock to avoid at least
    other worker instances from stealing the socket port

    :return: a (probably) free socket port
    """
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    addr, port = s.getsockname()
    s.close()
    return port


def import_module(name):
    """import module by absolute name
    """
    mod = __import__(name)
    components = name.split('.')
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


def import_test_by_name(name):
    """
        import the test module by its name
    """


    module_absolute_name = "%s.%s" % (ADAPTERS_PACKAGE,
                                      name)

    return import_module(module_absolute_name)

def get_hashes(file):
    """
    :return: sha256, sha1 and md5 of the file
    """

    file_content = ''
    with open(file,'rb') as f:
        file_content = f.read()
    sha256 = hashlib.sha256(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    md5 = hashlib.md5(file_content).hexdigest()
    return {'sha256' : sha256,
            'sha1' : sha1,
            'md5' : md5
            }

def get_av_avd_name(av_name):
    """
    convert the adapter name to its corresponding avd name

    Example: ComAntivirus to com.antivirus 
    """

    lowers = [i.lower() for i in re.findall('[A-Z][^A-Z]*',av_name)]

    return '.'.join(lowers)

def APKFileType(fname):
    """
    check if the file is an apk

    :return: path object of the apk
    """

    path = os.path.realpath(fname)

    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError('File %s does not exists' % fname)
    elif not fname.endswith('.apk'):
        raise argparse.ArgumentTypeError('File %s is not  an apk' % \
            fname.split('/')[-1])
    return path

class AV(object):
    """
    the AV object contains its adapter and avd name

    Example: ComAntivirus and com.antivirus
    """

    def __init__(self,av_name, avd_name):
        self.av_name = av_name
        self.avd_name = avd_name

class AVTypeAction(argparse.Action):
     """
     the AVTypeAction defines a custom action when parsing an antivirus name
     """

     def __call__(self,parser,namespace,values,option_string=None):
        current_avds = AVD.get_avds()
        av_dict = { av_name : get_av_avd_name(av_name) for av_name in values}
        
        avs = []
        for av_name, avd_name in av_dict.items():
            try:
                import_test_by_name(av_name)
            except:
                parser.error('Antivirus %s does not exists in adapters folder' % \
                            av_name)
            if avd_name not in current_avds:
                parser.error('Avd: %s for %s does not exists' % \
                            (avd_name, av_name))

            avs.append(AV(av_name,avd_name))

        setattr(namespace,self.dest,avs) 
