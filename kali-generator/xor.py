
import argparse
from ast import Bytes
from collections import namedtuple
import sys
import ctypes


def format_sc(sc):
    """Format the shellcode for pasting in C/C++, C#, Java, or Visual Basic projects.
    Takes shellcode as bytes, returns formatted bytes.
    """

    sc = ["{0:#0{1}x}".format(int(x),4) for x in sc] 

    CodeFormat = namedtuple('CodeFormat', 'open close heading items_per_line func')
  
    cf = CodeFormat(open='{\n', close='\n};', heading='byte[] shellcode = ', items_per_line=12, func=None)

    if cf.func:
        sc = cf.func

    iterations = (len(sc) // cf.items_per_line) if len(sc) % cf.items_per_line == 0 else (len(sc) // cf.items_per_line + 1)

    iteration = 0
    index = [0, cf.items_per_line]
    lines = []

    while iteration < iterations:
        line = ', '.join(sc[index[0]:index[1]])
        lines.append(line)
        index[0] = index[1]
        index[1] = index[1] + cf.items_per_line
        iteration += 1

    sc = ',\n'.join(lines)
    sc = cf.heading + cf.open + sc + cf.close

    return sc.encode()

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--inputfile', 
                        help='File containing shellcode or read from <stdin>')
						
parser.add_argument('-o', '--outputfile', 
                        help='Output file name')


args = parser.parse_args()

filename = args.inputfile

with open(filename,"rb") as f:
	buff = f.read()

def xor(buff):
	encoded  = [None] * len(buff)
	for i in range(0,len(buff)):
		encoded[i] = ((( buff[i] + 3) ^ 0xAA) & 0xFF)
	

	return encoded

e_buff = xor(buff)


#   //encoded[i] = (byte)((((uint) buf[i] + 3) ^ 0xAA) & 0xFF); //Encrypter
#    encoded[i] = (byte)((((uint)buf[i] ^ 0xAA) - 3) & 0xFF);  //Decrypter
output = args.outputfile
with open(output,"wb") as of:
	of.write(format_sc(e_buff))


