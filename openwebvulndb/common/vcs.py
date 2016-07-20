

class RepositoryChecker:

    async def has_content(self, repository):
        """
        Determines if the provided repository contains content or if the entry is bogus.

        Subversion:
           - Typical structure, tagged revisions
           - Direct version list
        """
        return False
