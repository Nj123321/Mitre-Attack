from git import Repo
import os
from stix2 import MemoryStore

# loader handles validatoins
class Loader:
    def __init__(self, remote_repo_url, local_copy_url):
        self.base_url = local_copy_url
        self.clone_or_update_repo(remote_repo_url, local_copy_url)
        
    def clone_or_update_repo(self, repo_url, dest_dir):
        if os.path.exists(dest_dir):
            print(f"Updating existing repo at {dest_dir}")
            repo = Repo(dest_dir)
            origin = repo.remotes.origin
            origin.pull()
        else:
            print(f"Cloning new repo from {repo_url} into {dest_dir}")
            Repo.clone_from(repo_url, dest_dir)
        print("finsihed cloning")
    def load_data(self, domain, version):
        """get ATT&CK STIX data for a given domain and version. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
        src = MemoryStore()
        if version == "latest":
            src.load_from_file(os.path.join(self.base_url, domain, f"{domain}.json"))
        else:
            src.load_from_file(os.path.join(self.base_url, domain, f"{domain}-{version}.json"))
        print ("finsihed loading in data")
        
        temp = []
        for x in src.query():
            if isinstance(x, dict):
                temp.append(x)
            else:
                temp.append(x.__dict__['_inner'])
        # verify valid x-mitre data?
        print("finished dictionizing in data")
        return temp
    def taxii_server(self):
        print("taxiserver")
        stix2.Relatinoship