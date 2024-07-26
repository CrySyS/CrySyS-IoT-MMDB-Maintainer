import os
import configparser
from py2neo import Graph
import preprocessing as prep
import init_graph as grph
import graph_maintenance as gm


def read_config(file_path):
	# Reads the configuration file and returns a dictionary with the settings.
	config = configparser.ConfigParser()
	config.read(file_path)

	settings = {
		"initalize_graph_flag": config.getboolean("Initialize_graph", "initalize_graph"),
		"dataset_src_dir_path": config.get("Initialize_graph", "dataset_src_dir_path"),
		"VT_report_src_dir_path": config.get("Initialize_graph", "VT_report_src_dir_path"),

		"initialize_dataset_flag": config.getboolean("Initialize_dataset", "initialize_dataset"),
		"dataset_src_root_dir_path": config.get("Initialize_dataset", "dataset_src_root_dir_path"),
		"dataset_input_src_dir_path": config.get("Initialize_dataset", "dataset_input_src_dir_path"),

		"architecture": config.get("Architecture", "arch"),

		"similarity_threshold": config.getfloat("Similarity_threshold", "threshold"),

		"endpoint_ip": config.get("Neo4j_client", "neo4j_uri"),
		"endpoint_passw": config.get("Neo4j_client", "neo4j_password"),
		"endpoint_usr": config.get("Neo4j_client", "neo4j_user"),

		"api_head": config.get("VT_API_header", "accept"),
		"api_key": config.get("VT_API_header", "apikey")
	}

	return settings


if __name__ == "__main__":
			
	# --> MAKE OUTPUT FOLDERS
	prep.create_output_folders()
	# Determine the base directory of the project
	base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	config_path = os.path.join(base_dir, 'config', 'config.ini')
	# Read the configuration file
	settings = read_config(config_path)

	# If the initialization flag for creating the graph is True, we first run the initialization process
	if (settings["initalize_graph_flag"]):
		# Initialize the graph
		grph.make_neo4j_graph(Graph(settings["endpoint_ip"], user=settings["endpoint_usr"], password=settings["endpoint_passw"]), settings["dataset_src_dir_path"], settings["VT_report_src_dir_path"], settings["architecture"], settings["similarity_threshold"])
		# Setup the config file to write
		config = configparser.ConfigParser()
		config.read(config_path)
		# Set the initalize_graph_flag to False
		config.set("Initialize_graph", "initalize_graph", str(False))
		# Write the config file
		try:
			with open(config_path, "w") as configfile:
				config.write(configfile)
		except Exception as e:
			print(f"Failed to write the config file: {e}")

	# If the initialization flag for use the dataset - for the first time - as an input is True, we first run the initialization process
	elif (settings["initialize_dataset_flag"]):
		# Load the location of the source folder where the unsorted malware samples are.
		srdp = prep.create_folder_tree()
		# Setup the config file to write
		config = configparser.ConfigParser()
		config.read(config_path)
		# Set the initialize_folders flag to False
		config.set("Initialize_dataset", "initialize_dataset", str(False))
		# Set the source_directory_path to srdp
		config.set("Initialize_dataset", "dataset_input_src_dir_path", srdp)
		# Write the config file
		try:
			with open(config_path, "w") as configfile:
				config.write(configfile)
		except Exception as e:
			print(f"Failed to write the config file: {e}")
		# Move the files to the correct folders
		prep.move_files(settings["dataset_src_root_dir_path"], srdp) # [OK]
		# Move the files to the correct folders for queue 1 with the chosen architecture
		prep.move_files_for_queue_one(srdp, settings["architecture"]) #[OK]

	else:
		# The location of the soruce folder where malware samples are loaded for processing.
		dir_path = settings["dataset_input_src_dir_path"]

		# Init neo4j client
		neo4j_uri = settings["endpoint_ip"]
		neo4j_user = settings["endpoint_usr"]
		neo4j_password = settings["endpoint_passw"]
		
		py2neo_graph = Graph(neo4j_uri, user=neo4j_user, password=neo4j_password)
		print("neo4j api client is initialized to py2neo_graph variable")

		# Create the VT API header
		headers = {
			"accept": settings["api_head"],
			"x-apikey": settings["api_key"]
		}

		# --> GRAPHS OPERATIONS
		grph.process_queue_one(py2neo_graph, dir_path, settings["similarity_threshold"])
		grph.process_queue_two(py2neo_graph, dir_path, headers, settings["similarity_threshold"])
		gm.sub(py2neo_graph)
		# --> MAINTENANCE
		# gm.check_first_submission_date(nx_graph, py2neo_graph, headers)
		gm.complete_node(py2neo_graph, headers)
		gm.check_insecure_samples(py2neo_graph, headers)