from .components import Loader, Parser, Repository
import os

class MitreAttackPipeline:
    def __init__(self, use_repo):
        self.loader = Loader(os.curdir + "/resources/mitre-attack-data", use_repo)
        self.parser = Parser()
        self.repository = Repository()
    
    def run(self, domain, version="latest"):
        data = self.loader.load_data(domain, version)
        parsed_data = self.parser.parse_data(data, domain)
        self.repository.load_database(parsed_data, domain)
        