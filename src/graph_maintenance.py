import os
import extractor as ex
from py2neo import Graph, Node, Relationship, Transaction, Subgraph, NodeMatcher, RelationshipMatcher
import json
import requests
import tlsh
import time
import logging
import datetime as dt
import init_graph as ig


# Get base directory of the project
def get_base_dir():
	# Get the base directory of the project
	return os.path.dirname(os.path.dirname(__file__))


# Check how many API calls are left for the day
def check_virustotal_quota(vt_header):
	# Get the VirusTotal user object to extract the quota infromation
	url = f"https://www.virustotal.com/api/v3/users/{vt_header['x-apikey']}"
	response = requests.get(url, headers=vt_header)
	user_data = response.json()
	quotas = user_data['data']['attributes']['quotas']['api_requests_daily']
	print("Quotas:", quotas)
	return quotas


# Wait until the next day to reset the quotas of the VirusTotal API calls
def wait_for_the_quotas_reset():
	# Get the current UTC date and time
	utc_now = dt.datetime.now(dt.timezone.utc)
	# Calculate the start of the next day in UTC
	next_day_start_utc = dt.datetime(utc_now.year, utc_now.month, utc_now.day, tzinfo=dt.timezone.utc) + dt.timedelta(days=1)
	# Calculate the duration until the start of the next day in UTC
	seconds_until_next_day = (next_day_start_utc - utc_now).total_seconds()
	# Sleep until the next day starts in UTC
	print(f"We have to wait for {int(seconds_until_next_day)} seconds.")
	time.sleep(seconds_until_next_day)
	print("Quota has been reset. You can proceed with API calls.")


# Check there is a valid first submission date for each node
def check_first_submission_date(py2neo_graph, vt_header):
	# List of vertices of the graph with the label 'Complete' and the first submission date '1900-01-01' and fix these nodes
	vertices_incorrect = py2neo_graph.nodes.match("Complete").where("_.first_submission_date = '1900-01-01'")
	for vertex in vertices_incorrect:
		# Get the VirusTotal report
		url = f"https://www.virustotal.com/api/v3/files/{vertex['sha256']}"
		response = requests.get(url, headers=vt_header)
		# Check that we haven't exceeded one of our quotas. If we have, we had to wait for the deadline whic is 00:00 UTC.
		if response.status_code == 429:
			wait_for_the_quotas_reset()
			# Get the VirusTotal report again
			response = requests.get(url, headers=vt_header)
		report_data = response.json()
		# Save the VirusTotal report
		with open(os.path.join(get_base_dir(), f"output/VT_reports/{vertex['sha256']}.json"), "w") as json_file:
			json.dump(report_data, json_file)
		# Convert the timestamp to a legit format for neo4j
		new_first_submission_date = ex.date_converter(report_data['data']['attributes']['first_submission_date'])
		# Update the py2neo_graph
		vertex['first_submission_date'] = new_first_submission_date
		# Update the local report
		# with open (os.path.join(get_base_dir(), f"output/local_reports/{vertex['architecture']}/{vertex['sha256']}.json"), "r") as json_file:
		with open (os.path.join(get_base_dir(), f"output/local_reports/{vertex['sha256']}.json"), "r") as json_file:
			local_data = json.load(json_file)
		local_data['first_submission_date'] = new_first_submission_date
		# Save the updated local report
		ex.validate_local_report(local_data)
		# Node pushed to the Neo4j database
		py2neo_graph.push(vertex)


# Get the VirusTotal report for each node with the label 'Incomplete' and update these nodes with the new attributes
def complete_node(py2neo_graph, vt_header):
	# Get the base directory of the project
	log_dir = os.path.join(get_base_dir(), "logs")
	# Create the logs directory if it does not exist
	os.makedirs(log_dir, exist_ok=True)
	# Configure the logging
	logging.basicConfig(filename = os.path.join(log_dir, "graph_maintenance.log"), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s')
	logging.info("The graph maintenance process has started to complete Incomplete labelled nodes.")
	# List of vertices of the graph woth tha label 'Incomplete'
	vertices_incomplete = py2neo_graph.nodes.match("Incomplete")
	for vertex in vertices_incomplete:
		# Get the VirusTotal report
		url = f"https://www.virustotal.com/api/v3/files/{vertex['sha256']}"
		response = requests.get(url, headers=vt_header)
		# Check that we haven't exceeded one of our quotas. If we have, we had to wait for the deadline which is 00:00 UTC
		if response.status_code == 429:
			wait_for_the_quotas_reset()
			# Get the VirusTotal report again
			response = requests.get(url, headers=vt_header)
		report_data = response.json()
		# If the node have a VirusTotal report, then:
		if response.status_code == 200:
			# Save the VirusTotal report
			with open(os.path.join(get_base_dir(), f"output/VT_reports/{vertex['sha256']}.json"), "w") as json_file:
				json.dump(report_data, json_file)
			# If the file is malicious
			if (report_data['data']['attributes']['last_analysis_stats']['malicious'] > 5):
				avclass_labels = ex.avclass_extractor(os.path.join(get_base_dir(), f"output/VT_reports/{vertex['sha256']}.json"))
				# Update and save the local report
				# with open (os.path.join(get_base_dir(), f"output/local_reports/{vertex['architecture']}/{vertex['sha256']}.json"), "r") as json_file:
				with open (os.path.join(get_base_dir(), f"output/local_reports/{vertex['sha256']}.json"), "r") as json_file:
					local_report_data = json.load(json_file)
					update_dictionary = {
							"av_labels_generation_date": ex.date_converter(report_data['data']['attributes']['last_analysis_date']),
							"positive_security_analysis": report_data['data']['attributes']['last_analysis_stats']['malicious'],
							"avclass_labels": ex.label_extractor(avclass_labels, 2),
							"first_submission_date": ex.date_converter(report_data['data']['attributes']['first_submission_date'])
						}
					local_report_data.update(update_dictionary)
					ex.validate_local_report(local_report_data)
				# Update the py2neo_graph Neo4j graph with the new attributes and labels
				# --> Properties
				update_dictionary.update({"avclass_labels": ex.label_extractor(avclass_labels, 1)})
				vertex.update(**update_dictionary)
				# --> Labels
				vertex.__primarylabel__ = "Node"
				vertex.add_label("Complete")
				vertex.remove_label("Incomplete")
				py2neo_graph.push(vertex)
				py2neo_graph.run("MATCH (n{sha256: '%s'}) REMOVE n:Incomplete" % (vertex['sha256']))
				logging.info(f"The node {vertex['sha256']} is updated.")
			# If the file is not malicious
			else:
				# Delete node
				print("[Not Malware] This node needs to be deleted:", vertex['sha256'])
				py2neo_graph.delete(vertex)
				logging.info(f"[Not Malware] This node needs to be deleted: {vertex['sha256']}")
		# If the file is not found on VirusTotal
		elif response.status_code == 404:
			#The sample cannot be found on VirusTotal
			print("[404] This node needs to be deleted:", vertex['sha256'])
			# Delete the node from py2neo_graph
			py2neo_graph.delete(vertex)
			# Log the deleted node
			logging.info(f"[404] This node needs to be deleted: {vertex['sha256']}")
	logging.info("The graph maintenance process has finished to complete Incomplete labelled nodes.")


# Check the nodes with the label 'Complete' and the attribute 'positive_security_analysis' less than 10 and reanalyze these nodes to check if they are truly malicious
def check_insecure_samples(py2neo_graph, vt_header):
	# Configure logging
	logging.basicConfig(filename="graph_maintenance.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s')
	logging.info("The graph maintanance process has started to check insecure samples.")
	# List of vertices
	vertex_insecure = []
	# Cypher query to get the nodes with the label 'Complete' and the attribute 'positive_security_analysis' less than 10
	query = """
	MATCH (n:Complete)
	WITH n,
		datetime(replace(n.av_labels_generation_date, ' ', 'T')).epochSeconds AS endTimestamp,
		datetime(replace(n.first_submission_date, ' ', 'T')).epochSeconds AS startTimestamp
	WHERE (endTimestamp - startTimestamp) <= 604800 AND
		n.positive_security_analysis <= 10
	RETURN (n)
	"""
	# Get theses nodes from the Neo4j graph database
	vertex_cursor = py2neo_graph.run(query)
	# From the result, get the nodes objects and append them to a list
	for cursor in vertex_cursor:
		vertex_insecure.append(cursor['n'])
	# For each node in the list, reanalyze the sample
	for vertex in vertex_insecure:
		# reanalyze the sample
		url = f"https://www.virustotal.com/api/v3/files/{vertex['sha256']}/analyse"
		response_analyse = requests.post(url, headers=vt_header)
		# quota exceeded
		if response_analyse.status_code == 429:
			# wait till tomorrow
			wait_for_the_quotas_reset()
			# get the VirusTotal analysis again
			response_analyse = requests.post(url, headers=vt_header)

		rescan_data = response_analyse.json()
		# if the sample is successfully submitted for analysis
		if response_analyse.status_code == 200:
			# wait for the analysis to be completed
			time.sleep(60)
			# Get the rescan id to check the analysis report
			rescan_id = rescan_data['data']['id']
			# Counter for resource access attempts
			ctr = 1
			# Analyses endpoint to get the analysis report
			url = f"https://www.virustotal.com/api/v3/analyses/{rescan_id}"
			response_analyse_report = requests.get(url, headers=vt_header)
			analysis_data = response_analyse_report.json()
			# wait until the analysis is completed
			while(analysis_data['data']['attributes']['status'] != "completed"):
				time.sleep(60)
				print(f"{ctr}. attempt to reach the resource {vertex['sha256']}, status: {analysis_data['data']['attributes']['status']}.")
				ctr = ctr + 1
				response_analyse_report =requests.get(url, headers=vt_header)
				analysis_data = response_analyse_report.json()
				print(analysis_data)

			# save the VirusTotal analysis report
			with open(os.path.join(get_base_dir(), f"output/VT_analyses/{vertex['sha256']}.json"), "w") as json_file:
				json.dump(analysis_data, json_file)

			# if the file malicious
			if analysis_data['data']['attributes']['stats']['malicious'] > 5:
				# download the new file report
				url = analysis_data['data']['links']['item']
				response = requests.get(url, headers=vt_header)
				# quota exceeded
				if response.status_code == 429:
					# wait till tomorrow
					wait_for_the_quotas_reset()
					# get the VirusTotal report again
					response = requests.get(url, headers=vt_header)
				report_data = response.json()
				# if the report is successfully downloaded from VirusTotal
				if response.status_code == 200:
					# saving the report
					with open(os.path.join(get_base_dir(), f"output/VT_reports/{vertex['sha256']}.json"), "w") as json_file:
						json.dump(report_data, json_file)
					# updating the node
					avclass_labels = ex.avclass_extractor(os.path.join(get_base_dir(), f"output/VT_reports/{vertex['sha256']}.json"))
					# update and save the local report
					# with open (os.path.join(get_base_dir(), f"output/local_reports/{vertex['architecture']}/{vertex['sha256']}.json"), "r") as json_file:
					with open (os.path.join(get_base_dir(), f"output/local_reports/{vertex['sha256']}.json"), "r") as json_file:
						local_report_data = json.load(json_file)
						update_dictionary = {
								"av_labels_generation_date": ex.date_converter(analysis_data['data']['attributes']['date']),
								"positive_security_analysis": analysis_data['data']['attributes']['stats']['malicious'],
								"avclass_labels": ex.label_extractor(avclass_labels, 2),
						}
						local_report_data.update(update_dictionary)
						ex.validate_local_report(local_report_data)

					# update the py2neo_graph Neo4j graph
					# --> Properties
					update_dictionary.update({"avclass_labels": ex.label_extractor(avclass_labels, 1)})
					update_vertex = py2neo_graph.nodes.match("Complete", sha256=f"{vertex['sha256']}").first()
					update_vertex.update(update_dictionary)
					# --> Labels
					update_vertex.__primarylabel__ = "Node"
					# push the node to the Neo4j database
					py2neo_graph.push(update_vertex)
					# --> Log
					logging.info(f"The node {vertex['sha256']} is updated.")

			# if the file not malicious
			else:
				# deleting the node
				print("[Not Malicious] This node needs to be deleted:", vertex['sha256'])
				delete_vertex = py2neo_graph.nodes.match("Complete", sha256=f"{vertex['sha256']}").first()
				py2neo_graph.delete(delete_vertex)
				logging.info(f"[Not Malware] This node needs to be deleted: {vertex['sha256']}")
	logging.info("The graph maintanance process has finished to check insecure samples.")


# Make relationships between the subgraph nodes and the incomplete nodes in the 'main' graph
def make_relationships(_subNode, _existingVertices):
	# List of tuples of hash pairs
	hash_pairs = []
	# The new node: sha256:tlsh pair
	key1 = _subNode['sha256']
	value1 = _subNode['tlsh']

	for vertex in _existingVertices:
		# The "existing" node sha256:tlsh pair
		key2 = vertex['sha256']
		value2 = vertex['tlsh']

		if ig.threshold(value1, value2):
			if not ig.uniqueness_test(key1, key2):
				_weight = tlsh.diff(value1, value2)
				hash_pairs.append((key1, value1, key2, value2, _weight))

	return hash_pairs


# Check the subgraph sub labelled nodes and make relationships - if any - with the incomplete labelled nodes in the 'main' graph
def sub(py2neo_graph):
		# Get the subgraph nodes
		query_sub = py2neo_graph.nodes.match("Sub")
		vertices_sub = [node for node in query_sub]
		# Get the incomplete nodes in the 'main' graph (except the subgraph nodes)
		query_without_label = py2neo_graph.run("MATCH (n:Incomplete) WHERE NOT (n:Sub) RETURN (n)")
		vertices_incomplete = [record["n"] for record in query_without_label]
		# For each subgraph node, make relationships with the incomplete nodes
		for sample in vertices_sub:
				hash_pairs = make_relationships(sample, vertices_incomplete)
				# If there is a relationship, create it
				if (len(hash_pairs) > 0):
					# Start a transaction to create the relationships between the nodes in the Neo4j graph database and remove the 'Sub' label from the subgraph nodes
					tx = py2neo_graph.begin()
					try:
						for hash_pair in hash_pairs:
							print(hash_pair)
							target_node = py2neo_graph.nodes.match(sha256=f"{hash_pair[2]}").first()
							relationship_to = Relationship(sample, 'TLSH_DIFF', target_node, weight=hash_pair[4])
							relationship_from = Relationship(target_node, 'TLSH_DIFF', sample, weight=hash_pair[4])
							tx.merge(relationship_to)
							tx.merge(relationship_from)
						tx.run("MATCH (n{sha256: '%s'}) REMOVE n:Sub" % (sample['sha256']))
						tx.commit()
					except Exception as e:
							print(e)
							tx.rollback()
				else:
					print(sample['sha256'], len(hash_pairs))
					py2neo_graph.run("MATCH (n{sha256: '%s'}) REMOVE n:Sub" % (sample['sha256']))

