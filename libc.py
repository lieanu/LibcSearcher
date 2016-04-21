#!/usr/bin/env python2

import os
import re
import sys
import struct
import logging
import logging.handlers
import subprocess

logging.basicConfig(format='%(asctime)s - %(filename)s:%(lineno)s - %(message)s',
                    level=logging.DEBUG)

class libc(object):
    def __init__(self, func=None, address=None):
        if isinstance(address, basestring):
            if address.startswith("0x"):
                address = address[2:]
            address = int(address, 16)

        self.condition = {}
        if func:
            self.condition[func] = address

        self.libc_database_path = os.path.join(os.path.abspath(os.path.dirname("__file__")), "libc-database/db/")

    def add_condition(self, func, address):
        if isinstance(address, basestring):
            if address.startswith("0x"):
                address = address[2:]
            address = int(address, 16)
        self.condition[func] = address

    def decided(self):
        """Wrapper for libc-database's find shell script.
        """
        if len(self.condition) == 0:
            logging.warning("No leaked info provided.\nPlease supply more info using \n\tadd_condition(leaked_func, leaked_address).")
            sys.exit(1)

        res = []
        for name, address in self.condition.items():
            addr_last12 = address & 0xfff
            res.append(re.compile("^%s .*%x" % (name, addr_last12)))

        db = self.libc_database_path
        files = []
        for _, _, f in os.walk(db):
            files += f

        result = []
        for ff in files:
            fd = open(db+ff, "r")
            data = fd.read().split("\n")
            flag = True
            for x in res:
                if any(map(lambda line:x.match(line), data)):
                    result.append(ff)
            fd.close()

        if len(result) == 0:
            logging.warning("No matched libc, try others.")
            sys.exit(1)

        if len(result) > 1:
            print "Multi Results:"
            for x in range(len(result)):
                print "%2d: %s" %(x, self.pmore(result[x]))
            print "Please supply more info using \n\tadd_condition(leaked_func, leaked_address)."
            while True:
                in_id = input("You can choose it by hand\nOr type 'exit' to quit:")
                if in_id == "exit" or in_id == "quit":
                    sys.exit(0)
                try:
                    in_id = int(in_id)
                    return result[in_id]
                except:
                    continue
        return result[0]

    def pmore(self, result):
        result = result[:-8] # .strip(".symbols")
        fd = open(self.libc_database_path+result+".info")
        info = fd.read().strip()
        return "%s (id %s)" % (info, result)

    def dump(self, func=None):

        db = self.decided()
        db = self.libc_database_path + db
        fd = open(db, "r")
        data = fd.read().strip("\n").split("\n")
        if not func:
            result = {}
            func = ["__libc_start_main_ret", "system", "dup2", "read", "write", "str_bin_sh"]
            for ff in func:
                for d in data:
                    f= d.split(" ")[0]
                    addr = d.split(" ")[1]
                    if ff == f:
                        result[ff] = int(addr, 16)
            for k, v in result.items():
                print k, hex(v)
            return result

        for d in data:
            f= d.split(" ")[0]
            addr = d.split(" ")[1]
            if func == f:
                return int(addr, 16)

        logging.warning("No matched, Make sure you supply a valid function name.")
        return 0

if __name__ == "__main__" :
    obj = libc("fgets", "7ff39014bd90")
    print "[+]system  offset: ", hex(obj.dump("system"))
    print "[+]/bin/sh offset: ", hex(obj.dump("str_bin_sh"))
