#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import json
import argparse

sys.path.append(os.path.abspath(os.path.join(os.getcwd(), "..")))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.core.plugins import import_plugin, list_plugins
from modules.processing.memory import VolatilityManager


def createDirBaseline():
    result = False

    try:
        create_folder(root=BASELINE_ROOT, folder='baseline')
        result = True
    except:
        pass

    return result


def startDefault():
    cuckoo_conf = Config("cuckoo")
    vmarch = cuckoo_conf.get("cuckoo").get("machinery")

    import_plugin("modules.machinery." + vmarch)
    machinery_plugin = list_plugins("machinery")[0]

    conf = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % vmarch)

    machinery = machinery_plugin()
    machinery.set_options(Config(vmarch))
    machinery.initialize(vmarch)

    return machinery


def startBaseline(machinery, vm):
    result = False

    cuckoo_conf = Config("cuckoo")
    vmarch = cuckoo_conf.get("cuckoo").get("machinery")

    try:
        # Starting VM
        machinery.start(vm.label)
        print "[INFO]: Starting VM " + vm.label + "."

		# Wait for connection
        time.sleep(10)

        # Create memory dump
        machinery.dump_memory(vm.label, MEMDUMP_ROOT + vm.label + ".dmp")
        print "[INFO]: Dumping VM " + vm.label + "."

        # Stopping VM
        machinery.stop(vm.label)
        print "[INFO]: Stopping VM " + vm.label + "."

        # Start analysis
        vm_conf = Config(vmarch)
        profile = vm_conf.get(vm.label).get("mem_profile")
        if not profile:
            profile =  Config("memory").basic.guest_profile

        dumppath = os.path.join(MEMDUMP_ROOT, vm.label + ".dmp")
        vol = VolatilityManager(memfile=dumppath, osprofile=profile)
        
        print "[INFO]: Volatility analysis started..."
        data = vol.run(manager=vmarch, vm=vm.label)

        # Write to JSON
        with open(MEMDUMP_ROOT + vm.label + '.json', 'w') as outfile:
            json.dump(data, outfile, sort_keys=False,
                      indent=4, encoding="utf-8")
        print "[INFO]: JSON dump of baseline VM " + vm.label + " succesfully created."

        # Delete memory dump
        os.remove(MEMDUMP_ROOT + vm.label + ".dmp")
        print "[INFO]: Memory dump of VM " + vm.label + " succesfully deleted."

        result = True
    except:
        pass

    return result


def main(args):
    if createDirBaseline():
        print '[INFO]: Baseline dir found.'
    else:
        print '[ERROR]: Baseline dir cannot be created.'
        sys.exit(0)

    machinery = startDefault()

    if args.s:
        vm_exist = False

        for vm in machinery.machines():
            if args.s == vm.label:
                vm_exist = True
                break

        if not vm_exist:
            print '[ERORR]: VM not found.'
            sys.exit(0)


    for vm in machinery.machines():
        if args.a:
            if startBaseline(machinery, vm):
                print '[INFO]: Baseline of ' + vm.label + ' created succesfully!'

        if args.s == vm.label:
            if startBaseline(machinery, vm):
                print '[INFO]: Baseline of ' + vm.label + ' created succesfully!'


if __name__ == "__main__":
    # Default paths
    BASELINE_ROOT = CUCKOO_ROOT + '/storage/'
    MEMDUMP_ROOT = BASELINE_ROOT + "baseline/"

    parser = argparse.ArgumentParser(description='Create a baseline for malware analysis.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', help='Select one VM to create a baseline.')
    group.add_argument('-a', action="store_true", help='Select all VM\'s to create a baseline.')
    args = parser.parse_args()

    main(args)

