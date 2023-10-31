from GithubRepoSearchModule.api import API
from GithubRepoSearchModule.githubRestConsumer import GithubRestConsumer

class SearchQueryConsumerFactory:

    @staticmethod
    def getConsumer(consumerType, query):
        if consumerType == API.GithubRest:
            return GithubRestConsumer(query)
        if consumerType == API.GithubGraphQL:
            raise NotImplementedError("graphQL consumer has not been implemented yet")
        return None
