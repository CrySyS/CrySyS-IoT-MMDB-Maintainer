import os
import json
import tlsh
import hashlib
import exiftool
import subprocess
import jsonschema
import datetime as dt


# validate the local report against the schema
def validate_local_report(_sample_dict):
	# open the schema file and store in the 'schema_data' variable
	with open('./resources/graph-based-malware-db-json.schema', 'r') as schema_file:
		schema_data = json.load(schema_file)
	# validate the sample dictionary against the schema
	try:
		jsonschema.validate(instance=_sample_dict, schema=schema_data)
		print("Validation successfull!")
		# write the sample features dictionary to a JSON file
		_path = (f"./outputs/local_reports/{_sample_dict['architecture']}/{_sample_dict['sha256']}.json")
		with open(_path, 'w') as report_file:
			json.dump(_sample_dict, report_file, indent=4)
		print(f"Data written to {_sample_dict['sha256']}.json file")
		return _sample_dict
	# if the validation fails, print 'Validation unsuccessful!' and the error
	except jsonschema.exceptions.ValidationError as e:
		print(f"Validation unsuccessful! {e}")
		raise e


# extract the AV labels from the sample by using the 'avclass' command
def avclass_extractor(json_file):
	# run the 'avclass' command on the sample and store the output in the 'av_labels' variable
	av_labels = subprocess.check_output(f"avclass -hash sha256 -f {json_file} -t",  shell=True, universal_newlines=True)
	#print(av_labels)
	# split the output by spaces and store the labels in the 'labels' variable
	labels = av_labels.split()[2].split(',')
	# filter the labels that contain 'FAM' (FAMILY) and store them in the 'filtered_labels' variable
	filtered_labels = [label for label in labels if 'FAM' in label]
	#print(filtered_labels)
	return filtered_labels


# extract the magic output from the sample by using the 'file' command
def magic_extractor(_sample):
	try:
		# run the 'file' command on the sample and store the output in the 'magic' variable
		magic = subprocess.check_output(f"file {_sample}", shell=True, universal_newlines=True)
		return magic
	# if the command fails, print 'Command failed with return code' and the return code
	except subprocess.CalledProcessError as e:
		print(f"Command failed with return code {e.returncode}")
		raise e


# extract the tags from the sample by using exiftool
def exiftool_extractor(_sample):
	# create an instance of the exiftool wrapper class
	with exiftool.ExifToolHelper() as et:
		tags = et.get_tags(_sample, None)
	# return the tags
	return tags[0]


# extract the entropy from the sample by using the 'bintropy' command
def entropy_extractor(_sample):
	try:
		# run the 'bintropy' command on the sample and store the output in the 'entropy' variable
		entropy = subprocess.check_output(f"bintropy --do-not-decide {_sample}", stderr=subprocess.DEVNULL, shell=True, universal_newlines=True)
		return float(entropy.split()[1])
	# if the command fails, print 'Command failed with return code' and the return code
	except subprocess.CalledProcessError as e:
		print(f"Command failed with return code {e.returncode}")
		raise e


# extract the CPU type of the sample
def cputype_extractor(_sample):
	# extract the tags from the sample by using exiftool
	_tags = exiftool_extractor(_sample)
	# check if the CPU type is ARM or MIPS and return the result
	try:
		# if the CPU type is ARM and the sample contains 'ARM' in the magic output, return 'ARM'
		if (_tags['EXE:CPUType'] == 40 or _tags['EXE:CPUType'] == 183) and ('ARM' in magic_extractor(_sample)):
			return 'ARM'
		# if the CPU type is MIPS and the sample contains 'MIPS' in the magic output, return 'MIPS'
		elif (_tags['EXE:CPUType'] == 8 or _tags['EXE:CPUType'] == 10) and ('MIPS' in magic_extractor(_sample)):
			return 'MIPS'
		# if the CPU type is not ARM or MIPS, print 'UNKNOWN' and the CPU type
		else:
			print('UNKNOWN:',_tags['EXE:CPUType'])
	# if the CPU type is not found, print 'Command failed with an error: Bad tag: EXE:CPUType'
	except KeyError as e:
		print(f"Command failed with an error: Bad tag: {e}")
		raise e


# extract the architecture of the sample (32-bit or 64-bit)
def architecture_extractor(_sample):
	# extract the tags from the sample by using exiftool
	_tags = exiftool_extractor(_sample)
	try:
		# if the CPU architecture is 1 (32-bit) and the sample contains '32-bit' in the magic output, return 32
		if (_tags['EXE:CPUArchitecture'] == 1) and ('32-bit' in magic_extractor(_sample)):
			return 32
		# if the CPU architecture is 2 (64-bit) and the sample contains '64-bit' in the magic output, return 64
		elif (_tags['EXE:CPUArchitecture'] == 2) and ('64-bit' in magic_extractor(_sample)):
			return 64
		else:
			# if the architecture is not 32-bit or 64-bit, print 'UNKNOWN' and the CPU type
			print('UNKNOWN:',_tags['EXE:CPUType'])
	# if the CPU architecture is not found, print 'Command failed with an error: Bad tag: EXE:CPUArchitecture'
	except KeyError as e:
		print(f"Command failed with an error: Bad tag: {e}")
		raise e


# extract the file type of the sample
def filetype_extractor(_sample):
	# extract the tags from the sample by using exiftool
	_tags = exiftool_extractor(_sample)
	# check if the file type is found and return the result
	try:
		return  _tags['File:FileType']
	# if the file type is not found, print 'Command failed with an error: Bad tag: File:FileType'
	except KeyError as e:
		print(f"Command failed with an error: Bad tag: {e}")
		raise e


# extract the size of the sample
def filesize_extractor(_sample):
	# extract the tags from the sample by using exiftool
	_tags = exiftool_extractor(_sample)
	# check if the file size is found and return the result
	try:
		return _tags['File:FileSize']
	# if the file size is not found, print 'Command failed with an error: Bad tag: File:FileSize'
	except KeyError as e:
		print(f"Command failed with an error: Bad tag: {e}")
		raise e


# extract the linking type of the sample
def magiclinking_extractor(_sample):
	# extract the magic output from the sample by using the 'file' command and store it in the 'magic_output' variable
	magic_output = magic_extractor(_sample)
	# check if the sample is statically or dynamically linked or unknown and return the result
	if 'statically linked' in magic_output:
		return 'statically linked'
	elif 'dynamically linked' in magic_output:
		return 'dynamically linked'
	else:
		return 'unknown'


# extract the hashes from the sample
def hash_extractor(_sample):
	# create instances of the hash functions
	md5_hash = hashlib.md5()
	sha1_hash = hashlib.sha1()
	sha256_hash = hashlib.sha256()
	tlsh_hash = tlsh.Tlsh()
	# open the sample file in binary mode
	with open(_sample, 'rb') as file:
		# read the file in chunks of 4096 bytes
		for chunk in iter(lambda: file.read(4096), b''):
			# update the hash functions with the read chunk
			md5_hash.update(chunk)
			sha1_hash.update(chunk)
			sha256_hash.update(chunk)
			tlsh_hash.update(chunk)
		tlsh_hash.final()
	# store the hash values in a dictionary
	hashes = {
			'md5': md5_hash.hexdigest(),
			'sha1': sha1_hash.hexdigest(),
			'sha256': sha256_hash.hexdigest(),
			'tlsh': tlsh_hash.hexdigest()
		 }
	return hashes


# convert the timestamp to a human-readable date format
def date_converter(_timestamp):
	return dt.datetime.utcfromtimestamp(_timestamp).strftime('%Y-%m-%d %H:%M:%S')


# extract the AV labels from the sample by using the 'avclass' command
def label_extractor(_label_list, extract_type):
	# input ~ ['FAM:mirai|20', 'FAM:gafgyt|5']
	# output based on extract_type:
	# 1 ~ ['mirai|20','gafgyt|5']
	# 2 ~ {'mirai' : 20, 'gafgyt': 5}
	# 3 ~ format 2 --> 1
	
	# if extract_type is 1, extract the labels and store them in the 'filtered_labels' variable as 'label|num'
	if extract_type == 1:
		filtered_labels = []
		for label in _label_list:
			filtered_labels.append(label.split(':')[1])
	# if extract_type is 2, extract the labels and store them in the 'filtered_labels' variable as {'label': num}
	elif extract_type == 2:
		filtered_labels = {}
		for label in _label_list:
			key, value = label.split(":")[1].split("|")
			int_value = int(value)
			filtered_labels.update({key: int_value})
	# if extract_type is 3, format the labels as 'label|num' from {'label': num} and store them in the 'filtered_labels' variable
	elif extract_type == 3:
		filtered_labels = []
		for label, num in _label_list.items():
			filtered_labels.append(label+'|'+str(num))
	# if extract_type is not 1, 2, or 3, return the original labels
	else:
		filtered_labels = _label_list

	return filtered_labels


# main function to extract all the features from the sample
def main(_node, _directory, _response_data = None, _label_extract_type = 0):
	path = os.path.join(_directory, _node)
	hashes = hash_extractor(path)
	sample_dict = {
		'architecture': cputype_extractor(path),
		'processor_bit_size': architecture_extractor(path),
		'file_type': filetype_extractor(path),
		'linking': magiclinking_extractor(path),
		'entropy': entropy_extractor(path),
		'size': filesize_extractor(path),
		'md5': hashes['md5'],
		'sha1': hashes['sha1'],
		'sha256': hashes['sha256'],
		'tlsh': hashes['tlsh']
	}
	# if the response data is not None, extract the additional features
	if _response_data is not None and _label_extract_type != 0:
		# update the sample dictionary with the additional features from the VirusTotal API response
		sample_dict.update({
				'av_labels_generation_date': date_converter(_response_data['data']['attributes']['last_analysis_date']),
				'positive_security_analysis': _response_data['data']['attributes']['last_analysis_stats']['malicious'],
				'avclass_labels': label_extractor(avclass_extractor(f"./outputs/VT_reports/{_node}.json"), _label_extract_type),
				'first_submission_date': date_converter(_response_data['data']['attributes']['first_submission_date'])
		})

	return validate_local_report(sample_dict)
