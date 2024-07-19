import configparser
from py2neo import Graph
import networkx as nx
import preprocessing as prep
import init_graph as grph
import graph_maintenance as gm


def read_config(file_path):
	#Reads the configuration file and returns a dictionary with the settings.
	config = configparser.ConfigParser()
	config.read(file_path)

	settings = {
		"source_root_dir_path": config.get("Folder_structure", "source_root_dir_path"),
		"initialize_folders": config.getboolean("Folder_structure", "initialize_folders"),
		"source_directory_path": config.get("Folder_structure", "source_directory_path"),
		"architecture": config.get("Architecture", "arch"),
		"endpoint_ip": config.get("Neo4j_client", "neo4j_uri"),
		"endpoint_passw": config.get("Neo4j_client", "neo4j_password"),
		"endpoint_usr": config.get("Neo4j_client", "neo4j_user"),
		"api_head": config.get("VT_API_header", "accept"),
		"api_key": config.get("VT_API_header", "apikey")
	}

	return settings


if __name__ == "__main__":

	settings = read_config("./config.ini")
	# If the initialization flag is True, we first run the initialization processes
	if (settings["initialize_folders"]):
		# Load the location of the source folder where the unsorted malware samples are.
		source_root_dir_path = settings["source_root_dir_path"]
		srdp = prep.create_folder_tree()
		# Setup the config file to write
		config = configparser.ConfigParser()
		config.read("./config.ini")
		# Set the initialize_folders flag to False
		config.set("Folder_structure", "initialize_folders", str(False))
		# Set the source_directory_path to srdp
		config.set("Folder_structure", "source_directory_path", srdp)
		# Write the config file
		try:
			with open("./config.ini", "w") as configfile:
				config.write(configfile)
		except Exception as e:
			print(f"Failed to write the config file: {e}")
		# Move the files to the correct folders
		prep.move_files(source_root_dir_path, srdp) # [OK]
		# Move the files to the correct folders for queue 1 with the chosen architecture
		prep.move_files_for_queue_one(srdp, settings["architecture"]) #[OK]
	else:
		# The location of the soruce folder where malware samples are loaded for processing.
		dir_path = settings["source_directory_path"]

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

		# --> GRAPH INITIALIZATION
		# grph.make_neo4j_graph(nx_graph, py2neo_graph)
		# --> GRAPHS OPERATIONS
		grph.process_queue_one(py2neo_graph, dir_path)
		grph.process_queue_two(py2neo_graph, dir_path, headers)
		gm.sub(py2neo_graph)
		# --> MAINTENANCE
		# gm.check_first_submission_date(nx_graph, py2neo_graph, headers)
		gm.complete_node(py2neo_graph, headers)
		gm.check_insecure_samples(py2neo_graph, headers)
