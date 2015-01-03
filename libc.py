#!/usr/bin/env python2

import os
import struct

class libc(object):
    def __init__(self, func, funcaddr):
        self.func = func
        if isinstance(funcaddr, (int, long)):
            self.funcaddr = funcaddr
        elif isinstance(funcaddr, basestring):
            if funcaddr.startswith("0x"):
                funcaddr = funcaddr[2:]
            self.funcaddr = int(funcaddr, 16)
        self.offset = self.funcaddr & 0xfff
        self.dbpath = os.path.join(os.path.split(os.path.realpath(__file__))[0], "database")
        self.all = self.__construct_dict()

    def __construct_dict(self):
        all = {}
        pfs = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}

        for root, dirs, files in os.walk(self.dbpath):
            for file in files:
                fd = open(os.path.join(self.dbpath, file), "r")
                mark = file.strip(".db")
                all[mark] = []
                for line in fd.readlines():
                    if line.startswith("0"):
                        line = line.strip("\n")
                        linelist = line.split(" ")
                        offset = struct.unpack(">" + pfs[len(linelist[0])*4], linelist[0].decode("hex"))[0]
                        all[mark].append((offset, linelist[-1]))
                fd.close()

        return all

    def __search(self):
        result = []
        for k, v in self.all.items():
            for pair in v:
                if (self.offset, self.func) == (pair[0]&0xfff, pair[1]):
                    if (k, pair) not in result:
                        result.append((k, pair))

        if len(result) == 1:
            return result[0]
        else:
            print "[x]  Multi Results, Choose it manually, First Default:  " 
            i = 0
            for item in result:
                print "     ID: ", i
                print "     Version         : ", item[0]
                print "     Function        : ", item[1][1]
                print "     Address         : ", hex(item[1][0])
                i += 1

            id = 0
            while True:
                try:
                    id = int(raw_input("Input a Number [0]: "))
                    if id < len(result):
                        break
                    else:
                        print "Invalid ID"
                except ValueError:
                    break
            return result[id]

    def base(self):
        (key, pair) = self.__search()
        return self.funcaddr - pair[0]

    def system_offset(self):
        (key, pair) = self.__search()
        for one in self.all[key]:
            if one[1] == "system":
                return one[0]

    def system_address(self):
        (key, pair) = self.__search()
        for one in self.all[key]:
            if one[1] == "system":
                return self.funcaddr - pair[0] + one[0]

    def offset_by_name(self, func):
        (key, pair) = self.__search()
        for one in self.all[key]:
            if one[1] == func:
                return one[0]

    def address_by_name(self, func):
        (key, pair) = self.__search()
        for one in self.all[key]:
            if one[1] == func:
                return self.funcaddr - pair[0] + one[0]


    def info(self):
        (key, pair) = self.__search()
        print "Libc Version: ", key
