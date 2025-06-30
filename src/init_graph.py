from py2neo import Graph, Node, Relationship, Transaction, Subgraph, NodeMatcher, RelationshipMatcher
import networkx as nx
import os
import shutil
import tlsh
import datetime as dt
from itertools import combinations
import extractor as ex
import requests
import json
import graph_maintenance as gm
import logging
import hashlib


# Get base directory of the project
def get_base_dir():
	# Get the base directory of the project
	return os.path.dirname(os.path.dirname(__file__))


# Load the malware samples sha256 value
def load_malware_samples(directory):
	# Return the list of the files in the directory
	return os.listdir(directory)


# Function to compare two TLSH values and return a boolean value based on the threshold value (default is 50) 
def threshold(a, b, i=50):
	# Calculate the difference between the two TLSH values
	score = tlsh.diff(a, b)
	# Return True if the difference is less than or equal to the threshold value
	return score <= i


# Function to compare two SHA-256 hash values and return a boolean value based on the uniqueness test
def uniqueness_test(a, b):
	# Return True if the two SHA-256 hash values are equal (if a and b are the same file)
	return a == b


# Function to create relationships between the new node and the existing vertices based on the TLSH values
def make_relationships(_graphNeo, _newNode, _existingVertices, _directoryPath, _threshold):
	# List of tuples of hash pairs
	hash_pairs = []
	# The new node: sha256:tlsh pair
	key1 = hashlib.sha256(open((os.path.join(_directoryPath, _newNode)), 'rb').read()).hexdigest()
	value1 = tlsh.hash(open((os.path.join(_directoryPath, _newNode)), 'rb').read())
	# Iterate through the existing vertices
	for vertex in _existingVertices:
		# The "existing" node sha256:tlsh pair
		key2 = vertex['sha256']
		value2 = vertex['tlsh']
		# Compare the TLSH values of the new node and the existing node
		if threshold(value1, value2, _threshold):
			# Check if the two nodes are unique
			if not uniqueness_test(key1, key2):
				# Calculate the weight of the relationship based on the TLSH difference
				_weight = tlsh.diff(value1, value2)
				# Append the new hash pairs|relationships to the list
				hash_pairs.append((key1, value1, key2, value2, _weight))
	# Return the list of hash pairs
	return hash_pairs


# Make neo4j graph from the NetworkX graph 
def make_neo4j_graph(py2neo_graph, bin_path, vt_path, arch, threshold):
	# Get the base directory of the project
	log_dir = os.path.join(get_base_dir(), "logs")
	# Create the logs directory if it does not exist
	os.makedirs(log_dir, exist_ok=True)
	# Configure the logging
	logging.basicConfig(filename = os.path.join(log_dir, "create_graph.log"), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s')
	logging.info("The graph creation process has started.")
	# Load the binaries with their path
	binaries = []
	for root_dir, _, filenames in os.walk(bin_path):
		for filename in filenames:
			# Append the binary to the list 
			binaries.append(
				{
					"filename": filename,
					"sha256": hashlib.sha256(open(os.path.join(root_dir, filename), 'rb').read()).hexdigest(),
					"path": root_dir, 
					"full_path": os.path.join(root_dir, filename),
					"arch": ex.cputype_extractor(os.path.join(root_dir, filename))
					}
				)
	# Create the graph
	# because the graph is empty, we need to create the nodes and relationships from the binaries and their VirusTotal reports
	for binary in binaries:
		# print(binary)
		if binary['arch'] != arch:
			logging.info(f"Processing the {binary['sha256']} sample. The architecture of the sample is {binary['arch']}. But the architecture of the graph is {arch}.")
			print(f"Processing the {binary['sha256']} sample. The architecture of the sample is {binary['arch']}. But the architecture of the graph is {arch}.")
			continue
		exit_loop = False
		for root_dir, _, filenames in os.walk(vt_path):
			log_this = True
			# Exit the loop if the VirusTotal report is found
			if exit_loop:
				break
			for filename in filenames:
				# Check if the file is a VirusTotal report and the SHA-256 hash value is equal to the binary's hash value
				if binary['sha256'] == filename.split('.')[0] and filename.endswith('.json'):
					log_this = False
					# Set the VirusTotal report path and exit the loop
					vt_report_path = os.path.join(root_dir, filename)
					exit_loop = True
					# Load the VirusTotal report
					with open(vt_report_path, "r") as json_file:
						vt_report = json.load(json_file)
					with open(os.path.join(get_base_dir(), f"output/VT_reports/{binary['sha256']}.json"), "w") as json_file:
						json.dump(vt_report, json_file)
					logging.info(f"The {binary['sha256']} sample has a VirusTotal report.")
					print(f"The {binary['sha256']} sample has a VirusTotal report.")

					# Get the metadata of the {binary} and save it to the local reports
					metadata = ex.main(binary['filename'], binary['path'], vt_report, 2)
					# Change the AV labels to the correct format to the neo4j database
					metadata['avclass_labels'] = ex.label_extractor(metadata['avclass_labels'], 3)
					# Merge the {binary} into the neo4j graph
					tx = py2neo_graph.begin()
					# All transactions(tx) will be a part of the "same" transaction to manage the consistency of the graph
					# Create the node with the metadata and merge it to the neo4j graph
					try: 
						node = Node(*["Complete", "Node"], **metadata)
						node.__primarylabel__ = "Node"
						node.__primarykey__ = "sha256"
						py2neo_graph.merge(node, "Node", "sha256")
						tx.commit()
						# Log the information and print the message to the console
						print(f"Node {metadata['sha256']} is created.")
						logging.info(f"Node {metadata['sha256']} is created.")
					# If there is an exception, rollback the transaction and log the error
					except Exception as e:
						tx.rollback()
						print(f"Failed to create the node {metadata['sha256']}. Error: {e}")
						logging.warning(f"Failed to create the node {metadata['sha256']} because of a(n) {type(e)}: {e}.")

					# List of vertices of the graph with all of the records filled
					query_result = py2neo_graph.nodes.match("Complete")
					# Get the complete labelled nodes from the graph and create the relationships between the new node and the existing vertices
					vertices_complete = [node for node in query_result]
					hash_pairs = make_relationships(py2neo_graph, binary['filename'], vertices_complete, binary['path'], threshold)
					tx = py2neo_graph.begin()
					# All transactions(tx) will be a part of the "same" transaction to manage the consistency of the graph
					# Create the relationships between the new node and the existing vertices
					# The primary label of the nodes is "Node" and the primary key is "sha256" to avoid the duplication of the nodes
					try:
						for hash_pair in hash_pairs:
							source_node = py2neo_graph.nodes.match("Complete", sha256=f"{hash_pair[0]}").first()
							source_node.__primarylabel__ = "Node"
							source_node.__primarykey__ = "sha256"
							target_node = py2neo_graph.nodes.match("Complete", sha256=f"{hash_pair[2]}").first()
							target_node.__primarylabel__ = "Node"
							target_node.__primarykey__ = "sha256"
							relationship_to = Relationship(source_node, 'TLSH_DIFF', target_node, weight=hash_pair[4])
							relationship_from = Relationship(target_node, 'TLSH_DIFF', source_node, weight=hash_pair[4])
							tx.merge(relationship_to)
							tx.merge(relationship_from)
						tx.commit()
						print(f"The transaction commit has done for {binary['sha256']} sample.")
						logging.info(f"The transaction commit has done for {binary['sha256']} sample.")
					# If there is an exception, rollback the transaction and log the error
					except Exception as e:
						tx.rollback()
						print(f"There was a(n) {type(e)}:", e)
						logging.warning(f"There was a(n) {type(e)}: {e}.")
					# Break the loop if the VirusTotal report is found and the relationships are created successfully
					break
		if log_this:
			logging.info(f"The {binary['sha256']} sample has no VirusTotal report.")
			print(f"The {binary['sha256']} sample has no VirusTotal report.")					
	logging.info("The graph creation process has finished.")


# Process the queue one
def process_queue_one(py2neo_graph, dir_path, threshold):
	# Get the base directory of the project
	log_dir = os.path.join(get_base_dir(), "logs")
	# Create the logs directory if it does not exist
	os.makedirs(log_dir, exist_ok=True)
	# Configure the logging
	logging.basicConfig(filename = os.path.join(log_dir, "queue_one.log"), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s')
	logging.info("The queue one processing has started.")
	# Define paths for the source and destination directories
	src_path = dir_path + "/Q1"
	dest_path_next = dir_path + "/Q2"
	dest_path_already = dir_path + "/ALREADY PROCESSED"

	# List of vertices of the graph with all of the records filled
	query_result = py2neo_graph.nodes.match("Complete")
	vertices_complete = [node for node in query_result]

	# Load the malware samples sha256 value
	samples = load_malware_samples(src_path)

	# Proccessing the samples in queue one
	for sample in samples:
		# Start the timer for processing one node
		start_time = dt.datetime.now()
		# Check if the sample is in the py2neo_graph
		if sample not in [node['sha256'] for node in vertices_complete]:
			# If the {sample} not in the py2neo_graph
			print(f"SHA256: {sample} not in the py2neo_graph")
			# Log the information
			logging.info(f"SHA256: {sample} not in the py2neo_graph")
			# Computing tlsh distance with complete labelled nodes and merge these relationships to the neo4j graph if the degree of the node is greater than 0
			hash_pairs_complete = make_relationships(py2neo_graph, sample, vertices_complete, src_path, threshold)
			print(f"{sample} node has {len(hash_pairs_complete)} complete adjacent nodes.")
			if (len(hash_pairs_complete) > 0):
				# All transactions(tx) will be a part of the "same" transaction to manage the consistency of the graph
				tx = py2neo_graph.begin()
				try:
					# Get the metadata of the {sample} and save it to the local reports
					metadata = ex.main(sample, src_path)
					# Merge the {sample} into the neo4j graph
					source_node = Node(*["Incomplete", "Node"], **metadata)
					source_node.__primarylabel__ = "Node"
					source_node.__primarykey__ = "sha256"
					# Merge the {sample} relationships with complete labelled nodes
					for hash_pair in hash_pairs_complete:
						target_node = py2neo_graph.nodes.match("Complete", sha256=f"{hash_pair[2]}").first()
						target_node.__primarylabel__ = "Node"
						target_node.__primarykey__ = "sha256"
						relationship_to = Relationship(source_node, 'TLSH_DIFF', target_node, weight=hash_pair[4])
						relationship_from = Relationship(target_node, 'TLSH_DIFF', source_node, weight=hash_pair[4])
						tx.merge(relationship_to)
						tx.merge(relationship_from)
					# Computing hash pairs with incomplete labelled nodes and merge these relationships to the neo4j graph
					query_result = py2neo_graph.nodes.match("Incomplete")
					vertices_incomplete = [node for node in query_result]
					hash_pairs_incomplete = make_relationships(py2neo_graph, sample, vertices_incomplete, src_path, threshold)
					print(f"{sample} node has {len(hash_pairs_incomplete)} incomplete adjacent nodes.")
					for hash_pair in hash_pairs_incomplete:
						target_node = py2neo_graph.nodes.match("Incomplete", sha256=f"{hash_pair[2]}").first()
						relationship_to = Relationship(source_node, 'TLSH_DIFF', target_node, weight=hash_pair[4])
						relationship_from = Relationship(target_node, 'TLSH_DIFF', source_node, weight=hash_pair[4])
						tx.merge(relationship_to)
						tx.merge(relationship_from)
					# Commit the transaction
					tx.commit()
					# Finish the timer for processing one node and log the information
					finish_time = dt.datetime.now()
					print(f"The transaction commit has done for {sample} sample. Elapsed time is:", (finish_time - start_time))
					logging.info(f"The transaction commit has done for {sample} sample.")
					logging.info(f"The {sample} has {len(hash_pairs_complete)} complete and {len(hash_pairs_incomplete)} incomplete adjacent nodes. Elapsed time is: {finish_time - start_time}.")
				# If there is an exception, rollback the transaction and log the error
				except Exception as e:
					tx.rollback()
					finish_time = dt.datetime.now()
					print(f"There was a(n) {type(e)}:", e, "Elapsed time is:", (finish_time - start_time))
					logging.warning(f"There was a(n) {type(e)}: {e}. Elapsed time is: {finish_time - start_time}")
			# Because the degree of these node is greater than 0, it is placed in the next processing queue.
			else:
				# Finish the timer for processing one node and log the information
				finish_time = dt.datetime.now()
				print(f"There is no edge between the {sample} and a single complete node. Elapsed time is:", (finish_time - start_time))
				logging.info(f"There is no edge between the {sample} and a single complete node. Elapsed time is: {finish_time - start_time}.")
				# Move the {sample} to the next processing queue directory (Q2) 
				try:
					shutil.move( (os.path.join(src_path, sample)), (os.path.join(dest_path_next, sample)) )
				# If there is an exception, log the error and continue to the next sample in the queue
				except Exception as e:
					print(f"Failed to move {sample}. Error: {e}")
					logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
		# If the {sample} is in the py2neo_graph
		else:
			# Finish the timer for processing one node and log the information
			finish_time = dt.datetime.now()
			print(f"SHA256: {sample} is in the py2neo_graph. Elapsed time is:", (finish_time - start_time))
			logging.info(f"SHA256: {sample} is in the py2neo_graph. Elapsed time is: {finish_time - start_time}.")
			# Move the {sample} to the already processed directory because it is already in the graph
			try:
				shutil.move( (os.path.join(src_path, sample)), (os.path.join(dest_path_already, sample)) )
			# If there is an exception, log the error and continue to the next sample in the queue
			except Exception as e:
				print(f"Failed to move {sample}. Error: {e}")
				logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
	logging.info("The queue one processing has finished.")


# Process the queue two
def process_queue_two(py2neo_graph, dir_path, vt_header, _threshold, nx_subgraph = None,):
	# Get the base directory of the project
	log_dir = os.path.join(get_base_dir(), "logs")
	# Create the logs directory if it does not exist
	os.makedirs(log_dir, exist_ok=True)
	# Configure the logging
	logging.basicConfig(filename = os.path.join(log_dir, "queue_two.log"), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s')
	logging.info("The queue two processing has started.")
	# Define paths
	src_path = dir_path + "/Q2"
	dest_path_na = dir_path + "/NOT FOUND"
	dest_path_benign = dir_path + "/NOT MALWARE"

	# Load the malware samples sha256 value
	samples = load_malware_samples(src_path)

	# Get current date for saving
	date = dt.date.today()

	if nx_subgraph is None:
		# Create the subgraph of the local nx_graph
		# --> NODES
		nx_subgraph = nx.DiGraph()
		for sample in samples:
			tlsh_value = tlsh.hash(open((os.path.join(src_path, sample)), 'rb').read())
			nx_subgraph.add_node(sample, **{'tlsh': tlsh_value})
		# print(list(nx_subgraph.nodes(data="tlsh")))
		# -->EDGES
		for (key1, value1), (key2, value2) in combinations({key: value for key, value in list(nx_subgraph.nodes(data="tlsh"))}.items(), 2):
			if threshold(value1, value2, _threshold):
				print(key1, value1, key2, value2, tlsh.diff(value1, value2))
				_weight = tlsh.diff(value1, value2)
				nx_subgraph.add_edge(key1, key2, weight=_weight)
				nx_subgraph.add_edge(key2, key1, weight=_weight)

	# 0 ~ false | 1 ~ true
	# If the no_need_to_restart flag is 0, the dominating set calculation is needed to be restarted
	# it is a flag to check if the calculation of the dominating set is need to be restarted or it is done successfully
	no_need_to_restart = 0
	while (no_need_to_restart == 0):
		# Calculate the dominating set of the subgraph and get the VT reports of the nodes in the dominating set if they are not downloaded yet 
		no_need_to_restart = 1
		print("Number of nodes:", nx.number_of_nodes(nx_subgraph))
		logging.info(f"Number of nodes: {nx.number_of_nodes(nx_subgraph)}")
		print("Number of edges:", nx.number_of_edges(nx_subgraph))
		logging.info(f"Number of edges: {nx.number_of_edges(nx_subgraph)}")
		dominating_set = nx.dominating_set(nx_subgraph)
		print("Numbef of dominating set:", len(dominating_set))
		logging.info(f"Number of nodes in the dominating set: {len(dominating_set)}")
		# Getting the VT reports using the dominating set
		for dominating_node in dominating_set:
			# Check if the report of the node is already downloaded or not
			if dominating_node not in [filename.split('.')[0] for filename in os.listdir(os.path.join(get_base_dir(), "output", "VT_reports"))]:
				# Get the VirusTotal report of the node using the VirusTotal API v3 
				url = f"https://www.virustotal.com/api/v3/files/{dominating_node}"
				response = requests.get(url, headers=vt_header)
				# If the response status code is 429, wait for the new quota meter and get the VirusTotal report again
				if response.status_code == 429:
					# Wait for the new quota meter
					gm.wait_for_the_quotas_reset()
					# Get the VirusTotal report again
					response = requests.get(url, headers=vt_header)
				# Get the report data from the response
				report_data = response.json()
				# If the response status code is 200, save the report data to the local file and log the information
				if response.status_code == 200:
					print(f"'{dominating_node}' has a successful VirusTotal report request.")
					logging.info(f"{dominating_node} has a successful VirusTotal report request")
					with open(os.path.join(get_base_dir(), f"output/VT_reports/{dominating_node}.json"), "w") as json_file:
						json.dump(report_data, json_file)
					# If the node is not malware, because the sample has been reported as malicious by less than or equal to 5 antivirus engines, delete the node from the subgraph and move the sample to the benign directory
					if (report_data['data']['attributes']['last_analysis_stats']['malicious']) <= 5:
						# If the node has no adjacent nodes, i.e. the degree of the node is less than or equal to 0, delete the node from the subgraph and move the sample to the benign directory, recalculating the dominating set is not needed
						if nx.degree(nx_subgraph, dominating_node) <= 0:
							nx_subgraph.remove_node(dominating_node)
							print("[Not Malware] This node needs to be deleted (clean delete):", dominating_node)
							logging.info(f"[Not Malware] This node {dominating_node} needs to be deleted (clean delete).")
							try:
								shutil.move( (os.path.join(src_path, dominating_node)), (os.path.join(dest_path_benign, dominating_node)) )
							except Exception as e:
								print(f"Faild to move {sample}. Error: {e}")
								logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
						# If the node has adjacent nodes, i.e. the degree of the node is greater than 0, delete the node from the subgraph, move the sample to the benign directory and restart the dominating set calculation
						elif nx.degree(nx_subgraph, dominating_node) > 0:
							nx_subgraph.remove_node(dominating_node)
							print("[Not Malware] This node needs to be deleted (dirty delete):", dominating_node)
							logging.info(f"[Not Malware] This node {dominating_node} needs to be deleted (dirty delete).")
							try:
								shutil.move( (os.path.join(src_path, dominating_node)), (os.path.join(dest_path_benign, dominating_node)) )
							except Exception as e:
								print(f"Faild to move {sample}. Error: {e}")
								logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
							# Save the subgraph to the local file and restart the dominating set calculation
							if not (os.path.exists(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"))):
								os.makedirs(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"), exist_ok=True)
							nx.write_gml(nx_subgraph, os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/queue_two-nx_sub_graph.gml"))
							no_need_to_restart = 0
							break
					# If the node is malware, i.e. the sample has been reported as malicious by more than 5 antivirus engines, update the node with the VT reports needed attributes
					else:
						# Update the node with the VT reports needed attributes
						metadata = ex.main(dominating_node, src_path, report_data, 2)
						nx_subgraph.nodes[dominating_node].update(metadata)
				# If the response status code is 404, because the report of the node is not found, delete the node from the subgraph and move the sample to the not found directory
				elif response.status_code == 404:
					# If the node has no adjacent nodes, i.e. the degree of the node is less than or equal to 0, delete the node from the subgraph and move the sample to the not found directory, recalculating the dominating set is not required
					if nx.degree(nx_subgraph, dominating_node) <= 0:
						nx_subgraph.remove_node(dominating_node)
						print("['404'] This node needs to be deleted (clean delete):", dominating_node)
						logging.info(f"['404'] This node {dominating_node} needs to be deleted (clean delete):")
						try:
							shutil.move( (os.path.join(src_path, dominating_node)), (os.path.join(dest_path_na, dominating_node)) )
						except Exception as e:
							print(f"Faild to move {sample}. Error: {e}")
							logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
					# If the node has adjacent nodes, i.e. the degree of the node is greater than 0, delete the node from the subgraph, move the sample to the not found directory and restart the dominating set calculation
					elif nx.degree(nx_subgraph, dominating_node) > 0:
						nx_subgraph.remove_node(dominating_node)
						print("['404'] This node needs to be deleted (dirty delete):", dominating_node)
						logging.info(f"['404'] This node {dominating_node} needs to be deleted (dirty delete):")
						try:
							shutil.move( (os.path.join(src_path, dominating_node)), (os.path.join(dest_path_na, dominating_node)) )
						except Exception as e:
							print(f"Faild to move {sample}. Error: {e}")
							logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
						# Save the subgraph to the local file and restart the dominating set calculation
						if not (os.path.exists(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"))):
							os.makedirs(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"), exist_ok=True)
						nx.write_gml(nx_subgraph, os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/queue_two-nx_sub_graph.gml"))
						no_need_to_restart = 0
						break
			# If the report of the node is already downloaded, update the node with the VT reports needed attributes
			# it can be happen if the node is in the dominating set and the report is already downloaded because of the previous calculations
			else:
				print(f"'{dominating_node}' has a downloaded VirusTotal report.")
				logging.info(f"'{dominating_node}' has a downloaded VirusTotal report.")
				with open(os.path.join(get_base_dir(), f"output/VT_reports/{dominating_node}.json"), "r") as json_file:
					report_data = json.load(json_file)
				# If the node is not malware, because the sample has been reported as malicious by less than or equal to 5 antivirus engines, delete the node from the subgraph and move the sample to the benign directory
				if (report_data['data']['attributes']['last_analysis_stats']['malicious']) <= 5:
					if nx.degree(nx_subgraph, dominating_node) <= 0:
						nx_subgraph.remove_node(dominating_node)
						print("[Not Malware] This node needs to be deleted (clean delete):", dominating_node)
						logging.info(f"[Not Malware] This node {dominating_node} needs to be deleted (clean delete).")
						try:
							shutil.move( (os.path.join(src_path, dominating_node)), (os.path.join(dest_path_benign, dominating_node)) )
						except Exception as e:
							print(f"Faild to move {sample}. Error: {e}")
							logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
					# If the node has adjacent nodes, i.e. the degree of the node is greater than 0, delete the node from the subgraph, move the sample to the benign directory and restart the dominating set calculation
					elif nx.degree(nx_subgraph, dominating_node) > 0:
						nx_subgraph.remove_node(dominating_node)
						print("[Not Malware] This node needs to be deleted (dirty delete):", dominating_node)
						logging.info(f"[Not Malware] This node {dominating_node} needs to be deleted (dirty delete).")
						try:
							shutil.move( (os.path.join(src_path, dominating_node)), (os.path.join(dest_path_benign, dominating_node)) )
						except Exception as e:
							print(f"Faild to move {sample}. Error: {e}")
							logging.warning(f"Failed to move {sample} because of a(n) {type(e)}: {e}.")
						# Save the subgraph to the local file and restart the dominating set calculation
						if not (os.path.exists(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"))):
							os.makedirs(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"), exist_ok=True)
						nx.write_gml(nx_subgraph, os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/queue_two-nx_sub_graph.gml"))
						no_need_to_restart = 0
						break
				# Otherwise, update the attributes of the node using the VT reports.
				else:
					# if the node has not yet been updated, update the node with all the attributes we extract for a sample and update the dominating set
					if 'sha256' not in nx_subgraph.nodes[dominating_node]:
						metadata = ex.main(dominating_node, src_path, report_data, 2)
						nx_subgraph.nodes[dominating_node].update(metadata)

	# Get all nodes without attributes and update them with the corrresponding metadata
	all_nodes_without_attributes = [node for node in nx_subgraph.nodes() if 'sha256' not in nx_subgraph.nodes[node]]
	for node in all_nodes_without_attributes:
		# Check if the report of the node is already downloaded or not, if not and update the metadata based on that information
		if node not in [report_name.split('.')[0] for report_name in os.listdir(os.path.join(get_base_dir(), "output", "VT_reports"))]:
			metadata = ex.main(node, src_path)
			nx_subgraph.nodes[node].update(metadata)
		else:
			with open(os.path.join(get_base_dir(), f"output/VT_reports/{node}.json"), "r") as json_file:
				report_data = json.load(json_file)
			metadata = ex.main(node, src_path, report_data, 2)
			nx_subgraph.nodes[node].update(metadata)
	# Save the subgraph to the local file for any furter verification processes
	if not (os.path.exists(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"))):
		os.makedirs(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"), exist_ok=True)
	nx.write_gml(nx_subgraph, os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/queue_two-nx_sub_graph.gml"))

	# Get all nodes with all the attributes as a list of dictionaries
	all_nodes_with_attributes = [nx_subgraph.nodes[node] for node in nx_subgraph.nodes]
	all_edges_with_attributes = [(u, v, nx_subgraph[u][v]) for u, v in nx_subgraph.edges()]
	# Commit the nodes and edges to the neo4j graph
	for node in all_nodes_with_attributes:
		# All transactions(tx) will be a part of the "same" transaction to manage the consistency of the graph
		tx = py2neo_graph.begin()
		# Start the timer for processing one node
		start_time = dt.datetime.now()
		# Merge the node into the neo4j graph
		try:
			# If the node has all the attributes, i.e. the node is complete, merge the node with the complete label
			if (len(node) == 14):
				labels = ["Node", "Complete", "Sub"]
				node_to_upload = Node(*labels, **node)
				node_to_upload['avclass_labels'] = ex.label_extractor(node_to_upload['avclass_labels'], 3)
			# If the node has not all the attributes, i.e. the node is incomplete, merge the node with the incomplete label and Sub label to indicate that the node is in the subgraph
			else:
				labels = ["Node", "Incomplete", "Sub"]
				node_to_upload = Node(*labels, **node)
			tx.merge(node_to_upload, "Node", "sha256")
			# Finish the timer for processing one node and log the information
			finish_time = dt.datetime.now()
			# Commit the transaction
			tx.commit()
			print(f"The transaction commit has done for {node} sample. Elapsed time is:", (finish_time - start_time))
			logging.info(f"The transaction commit has done for {node} sample. Elapsed time is: {(finish_time - start_time)}")
		# If there is an exception, rollback the transaction and log the error
		except Exception as e:
			tx.rollback()
			finish_time = dt.datetime.now()
			print(f"There was a(n) {type(e)}:", e, "Elapsed time is:", (finish_time - start_time))
			logging.warning(f"There was a(n) {type(e)}: {e}. Elapsed time is: {finish_time - start_time}")
	# Do the same for the edges as we did for the nodes
	for edge in all_edges_with_attributes:
		# All transactions(tx) will be a part of the "same" transaction to manage the consistency of the graph
		tx = py2neo_graph.begin()
		# Start the timer for processing one edge
		start_time = dt.datetime.now()
		try:
			# Get the source and target nodes of the edge
			print(edge)
			source_node = Node("Node", sha256=edge[0])
			source_node.__primarylabel__ = "Node"
			source_node.__primarykey__ = "sha256"
			print(source_node)
			target_node = Node("Node", sha256=edge[1])
			target_node.__primarylabel__ = "Node"
			target_node.__primarykey__ = "sha256"
			print(target_node)
			# The weight of the edge is the TLSH difference between the source and target nodes
			_weight = edge[2]['weight']
			relationship = Relationship(source_node, 'TLSH_DIFF', target_node, weight=_weight)
			# Merge the relationship into the neo4j graph and commit the transaction
			tx.merge(relationship)
			tx.commit()
			# Finish the timer for processing one edge and log the information
			finish_time = dt.datetime.now()
			print(f"The transaction commit has done for {edge} edge. Elapsed time is:", (finish_time - start_time))
			logging.info(f"The transaction commit has done for {edge} edge. Elapsed time is: {(finish_time - start_time)}")
		# If there is an exception, rollback the transaction and log the error
		except Exception as e:
			tx.rollback()
			finish_time = dt.datetime.now()
			print(f"There was a(n) {type(e)}:", e, "Elapsed time is:", (finish_time - start_time))
			logging.warning(f"There was a(n) {type(e)}: {e}. Elapsed time is: {finish_time - start_time}")
	# Commit the transaction, save the graph and add the subgraph to the graph:
	if not (os.path.exists(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"))):
		os.makedirs(os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/"), exist_ok=True)
	nx.write_gml(nx_subgraph, os.path.join(get_base_dir(), f"output/temp_graphs/queue_two/{date}/queue_two-nx_sub_graph.gml"))
	print("Graphed saved!")
	logging.info("The queue two processing has finished.")
