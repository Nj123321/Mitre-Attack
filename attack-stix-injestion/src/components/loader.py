from git import Repo
import os
from stix2 import parse
import json
import requests

# loader handles validatoins
class Loader:
    MITRE_RAW_REPO_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    MITRE_ORIGIN_REPO_URL = "https://github.com/mitre-attack/attack-stix-data.git"

    def __init__(self, local_copy_url, use_repo):
        self.local_copy_url = local_copy_url
        self.use_repo = use_repo
        if use_repo:
            self.clone_or_update_repo(Loader.MITRE_ORIGIN_REPO_URL, local_copy_url)
        
    def clone_or_update_repo(self, repo_url, dest_dir):
        if os.path.exists(dest_dir):
            print(f"Updating existing repo at {dest_dir}")
            repo = Repo(dest_dir)
            repo.remotes.origin.pull()
        else:
            print(f"Cloning new repo from {repo_url} into {dest_dir}")
            Repo.clone_from(repo_url, dest_dir)
        print("finished")
        
    def load_data(self, domain, version):
        """get ATT&CK STIX data for a given domain and version. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
        data_path =  self.file_path(domain, version)
        loaded_data = None
        if self.use_repo:
            with open(os.path.join(self.local_copy_url, data_path), "r") as f:
                loaded_data = json.load(f)
        else:
            loaded_data = requests.get(os.path.join(Loader.MITRE_RAW_REPO_URL, data_path)).json()
        print("finished loading data")
        parse(loaded_data, version="2.1", allow_custom=True)
        print ("finsihed validiating data")
        return loaded_data["objects"]
    
    def file_path(self, domain, version):
        if version == "latest":
            return os.path.join(domain, f"{domain}.json")
        else:
            return os.path.join(domain, f"{domain}-{version}.json")