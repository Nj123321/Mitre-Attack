from components import Loader, Parser, Repository
import os

class MitreAttackPipeline:
    def __init__(self, url):
        self.loader = Loader(url, os.curdir + "/resources/mitre-attack-data")
        self.parser = Parser()
        self.repository = Repository()
    
    def run(self, domain):
        data = self.loader.load_data(domain)
        parsed_data = self.parser.parse_data(data, domain)
        self.repository.load_database(parsed_data, domain)
        