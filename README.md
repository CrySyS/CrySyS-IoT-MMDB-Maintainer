# CrySyS-IoT-MMDB-Maintainer

## Initialization

The software communicates with the Neo4j database via the API provided by Py2neo, so the existence of a Neo4j database is necessary for the software to work correctly. The Neo4j database URL must therefore be specified in the `config/config.ini` configuration file. Then, if the database is still empty, there are two ways to initialize it:
1. Import a dump file.
2. ELF binaries and their VirusTotal reports.

For initialization with an already existing database, we recommend our dataset called [CrySyS-IoT-MMDB-2024](https://github.com/CrySyS/CrySyS-IoT-MMDB-2024). To import a database into Neo4j, issue the following command:
```
neo4j-admin database load --from-path=/var/lib/neo4j/import --overwrite-destination=true --verbose neo4j
```

For the second method in the `config/config.ini` configuration file, the `[Initialize_graph]` block should be set, where the absolute path of the root directory of the ELF binaries and the VirusTotal reports should be entered.

Since the graph database is based on similarity, the metadata of ELF binaries processed in dump files is separate per architecture. The software currently supports ARM and MIPS architectures.

## Execution of the code

Run the `main.py` file from the `src` folder with at least python 3.10.

## Input

### Configuration file

#### `[Initialize_graph]`

- `initalize_graph` is true if the graph has not yet been initialized, otherwise it should be false if a neo4j graph already exists.
- `dataset_src_dir_path` is the absolute path of the root directory of the ELF binaries.
- `VT_report_src_dir_path` is the absoulute path of the root directory of the corresponding VirusTotal reports.

#### `[Initialize_dataset]`

- `initialize_dataset` is false if the initialization folders do not exist, otherwise it is true.
- `dataset_src_root_dir_path` is the path to the root directory of the dataset.
- `dataset_input_src_dir_path` - The software creates a folder structure for processing ELF binaries in the dataset, the path to which is automatically inserted in this option of the configuration file.

#### `[Architecture]`

- `arch` determines the architecture of the ELF binaries that will be used to build the database.

#### `[Similarity threshold]`

- `threshold` - We use the TLSH to compute the similarity between two nodes in the graph, and the threshold is used to determine whether or not two nodes are considered similar.

#### `[Neo4j_client]`

- `neo4j_uri` is the URI of the Neo4j database to connect to (by default bolt://localhost:7687).
- `neo4j_user`is the name of the user account that will be used to access the database (by default neo4j).
- `neo4j_password` is the password of the user account that will be used to access the database (by default neo4j).

#### `[VT_API_header]`

- `accept` should be `application/json`.
- `apikey` is the VirusTotal API key.

## Output folder contents

The output folder contains three additional subfolders that store the information generated during the processing of binaries as follows:
- `local_reports`: For each ELF binary, `json` files containing the metadata defined in the `graph-based-malware-db-json.schema` file.
- `temp_graphs`: Temporary graph files.
- `VT_analyses`: The results of VirusTotal Analyses for each ELF binaries.
- `VT_reports`: The results of VirusTotal Reports for each ELF binaries.

## Requirements

### VirusTotal

To use the software correctly, it is essential to have a valid VirusTotal API v3 key.

### List of external libaries/softwares

| Name        | Version     |  Available at                                   |
| ----------- | ----------- | ----------------------------------------------- |
| Neo4j       | 5.18.1      | https://neo4j.com/                              |
| PyExifTool  | 0.5.6       | https://pypi.org/project/PyExifTool/            |
| bintropy    |             | https://github.com/packing-box/bintropy         |
| python-tlsh | 4.5.0       | https://pypi.org/project/python-tlsh/           |
| jsonschema  | 4.22.0      | https://github.com/python-jsonschema/jsonschema |
| AVClass     | v2          | https://github.com/malicialab/avclass           |
| NetworkX    | 3.3         | https://networkx.org/                           |
| Py2neo      | 2021.1      | https://neo4j-contrib.github.io/py2neo/         |

## Acknowledgement

The research presented in this paper was supported by the European Union project RRF-2.3.1-21-2022-00004 within the framework of the Artificial Intelligence National Laboratory and by the European Union’s Horizon Europe Research and Innovation Program through the [DOSS Project](https://dossproject.eu/) (Grant Number 101120270). The presented work also builds on results of the [SETIT Project](https://www.crysys.hu/research/setit/) (2018-1.2.1-NKP-2018-00004), which was implemented with the support provided from the [National Research, Development and Innovation Fund of Hungary](https://mi.nemzetilabor.hu/), financed under the 2018-1.2.1-NKP funding scheme. The authors are also thankful to [VirusTotal](https://www.virustotal.com/) for the academic license provided for research purposes.