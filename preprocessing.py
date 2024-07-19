import re
import os
import uuid
import shutil
import datetime as dt
import extractor as ex


def create_folder_tree():
	# Get the current date in YYYYMMDD format
	date_str = dt.datetime.now().strftime("%Y%m%d")
	# Generate a random UUID and convert to a string
	dataset_id = str(uuid.uuid4())
	# Define the base directory
	base_dir = f"./resources/SORTED_DATASET_{date_str}_{dataset_id}"
	# Check if the specific base directory already exists
	if os.path.exists(base_dir):
		return f"Directory already exists: {base_dir}"

	# List of directories to create
	directories = [
		f"{base_dir}/RAW/ARM",
		f"{base_dir}/RAW/MIPS",
		f"{base_dir}/RAW/OTHERS",
		f"{base_dir}/Q1",
		f"{base_dir}/Q2",
		f"{base_dir}/NOT FOUND",
		f"{base_dir}/NOT MALWARE",
		f"{base_dir}/ALREADY PROCESSED"
	]

	# Create each directory
	for directory in directories:
		os.makedirs(directory, exist_ok=True)
	# Return the base directory for reference
	return base_dir


def move_files(source_folder, destination_folder):
	# Check if the source folder exists
	if not os.path.exists(source_folder):
		print(f"Source folder '{source_folder}' does not exist.")
	# Iterate through the files and subdirectories in the source folder using 'os.walk'
	# root ~ the current directory that being scanned
	# _ ~ list of subdirectories
	# files ~ list of the files in the current directory
	for root, _, files in os.walk(source_folder):
		# Iterate through the files in the current directory
		for file in files:
			# os.path.join creates the full path of the file
			source_file = os.path.join(root, file)
			# Extract the architecture of the file
			try:
				# Extract the CPU type of the file
				cputype = ex.cputype_extractor(source_file)
				if cputype not in ["ARM", "MIPS"]:
					cputype = "OTHERS"
			# If an exception occurs, set the CPU type to 'OTHERS'
			except Exception as e:
				cputype = "OTHERS"
			# Define the destination directory based on the cputype
			destination_directory = f"{destination_folder}/RAW/{cputype}"
			# Check if the destination directory exists, if not create it
			if not os.path.exists(destination_directory):
				os.makedirs(destination_directory, exist_ok=True)
			# Define the full path of the destination file
			destination_file = os.path.join(destination_directory, file)
			# Move the file to the destination directory
			print(f"Moved: {source_file} -> {destination_file}")
			# Move the file to the destination directory
			shutil.move(source_file, destination_file)
			# Check if the file is a valid SHA-256 hash
			check_sha256(destination_file)


# Function to check if the file name is a valid SHA-256 hash
def check_sha256(file):
	# Define a regular expression pattern to match a SHA-256 hash value
	# re.compile is a method in Python that compiles a regular expression pattern into a regular expression object which can be used for regex-related operations
	# The pattern ^[a-fA-F0-9]{64}$ matches a string that consists of exactly 64 characters, where each character is a hexadecimal digit (0-9, a-f, A-F)
	sha256_pattern = re.compile(r"^[a-fA-F0-9]{64}$")
	
	# Split the file path into a list of directories and the file name
	splitted_path = file.split("/")
	# Get the index of the last part of the file path (the file name)
	filename_idx = len(splitted_path) - 1
	# Check if the last part of the file path (the file name) is a valid SHA-256 hash
	is_sha256 = bool(sha256_pattern.match(splitted_path[filename_idx]))

	if is_sha256:
		print(f"'{splitted_path[filename_idx]}' is valid SHA-256 hash.")
	# If the file name is not a valid SHA-256 hash, rename the file for the file SHA-256 hash
	else:
		print(f"'{splitted_path[filename_idx]}' is not valid SHA-256 hash.")
		# Rename the file with the corresponding SHA-256 hash value
		file_hashes = ex.hash_extractor(file)
		# Replace the file name with the corresponding SHA-256 hash value
		splitted_path[filename_idx] = file_hashes['sha256']
		# Join the list of directories and the new file name to create the new file path
		new_file = "/".join(splitted_path)
		# Rename the file
		os.rename(file, new_file)
		print(f"Renamed: {file} -> {new_file}")


# Function to move files to the correct folders for queue 1 based on the chosen architecture
def move_files_for_queue_one(root_folder, architecture):
	# Define the source and destination directories
	src_dir_path = root_folder + "/RAW/" + architecture
	dest_dir_path = root_folder + "/Q1"
	# Check if the source directory exists
	files = os.listdir(src_dir_path)
	# Move each file to the destination directory
	for file in files:
		src_file = os.path.join(src_dir_path, file)
		dest_file = os.path.join(dest_dir_path, file)
		# Check if it's a file and not a directory
		if os.path.isfile(src_file):
			try:
				# Move the file to the destination directory
				shutil.copy2(src_file, dest_file)
				print(f"Copied: {src_file} to {dest_file}")
			# If the copying fails, print an error message
			except Exception as e:
				print(f"Failed to copy {src_file}. Error: {e}")
		# If it's a directory, skip it
		else:
			print(f"Skipped: {src_file} (Not a file)")


def move_files_for_queue_two():
	with open("./outputs/for_manual_process/queue_2.txt", "r") as file:
		for line in file:
			file_name = line.split("/")[4][0:64]

			source_file = f"./resources/SortedDatasetD-1/ARM/{file_name}"
			destination_file = f"./resources/SortedDatasetD-1/ARM_Q2/{file_name}"
			shutil.move(source_file, destination_file)
	print("JOB DONE")

