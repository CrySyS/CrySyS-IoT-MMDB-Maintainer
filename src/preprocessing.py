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
	dataset_dir = os.path.normpath(f"input/SORTED_DATASET_{date_str}_{dataset_id}")
	base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), dataset_dir)
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
		f"{base_dir}/ALREADY PROCESSED",
	]

	# Create each directory
	for directory in directories:
		os.makedirs(directory, exist_ok=True)
	# Return the base directory for reference
	return base_dir


def create_output_folders():
	# Get the base directory of the project
	base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	# List of directories to create
	directories = [
		f"{base_dir}/output/local_reports",
		f"{base_dir}/output/VT_analyses",
		f"{base_dir}/output/VT_reports",
	]
	# Create each directory
	for directory in directories:
		os.makedirs(directory, exist_ok=True)


def move_files(source_folder, destination_folder):
	# Check if the source folder exists
	if not os.path.exists(source_folder):
		# Raise an exception if the source folder does not exist and provide a hint to the user to check the path in the 'config.ini' file.
		raise Exception(f"Source folder '{source_folder}' does not exist. You may have entered an incorrect path to the dataset directory. Change the path in the 'config.ini' file.")
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
			# Name the destination file based on the SHA-256 hash of the source file
			sha256_hash = ex.hash_extractor(source_file)['sha256']
			# Define the full path of the destination file
			destination_file = os.path.join(destination_directory, sha256_hash)
			# Create a soft link to the source file in the destination directory
			os.symlink(source_file, destination_file, target_is_directory=False)
			# Print the source and destination file paths for debugging purposes
			print(f"Sym link created: {destination_file} -> {source_file}")


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
				shutil.move(src_file, dest_file)
				print(f"Moved: {src_file} to {dest_file}")
			# If the copying fails, print an error message
			except Exception as e:
				print(f"Failed to move {src_file}. Error: {e}")
		# If it's a directory, skip it
		else:
			print(f"Skipped: {src_file} (Not a file)")
