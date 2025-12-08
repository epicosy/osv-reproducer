from typing import List
from abc import abstractmethod

from osvutils.types.osv import OSV
from ..models import ProjectRange


class OSVInterface:
    @abstractmethod
    def fetch_vulnerability(self, osv_id: str) -> OSV:
        """
        An abstract method that retrieves vulnerability data based on an OSV identifier.

        The method must be implemented by any subclass, and it is intended to define
        the contract for fetching detailed vulnerability information from an appropriate
        source or database using a unique identifier defined by the OSV schema.

        Args:
            osv_id (str): The unique identifier of the vulnerability described in the
            OSV schema.

        Returns:
            OSV: An instance of the OSV class containing detailed information about
            the requested vulnerability.

        Raises:
            NotImplementedError: This method must be implemented in a subclass and will
            raise this error if called directly from the base class.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_project_ranges(self, osv: OSV) -> List[ProjectRange]:
        """
        Represents the abstract definition for obtaining project ranges associated
        with a given OSV (Open Source Vulnerability) instance. Ensures any subclass
        implements the required functionality to retrieve project ranges.

        Parameters
        ----------
        osv : OSV
            An instance representing the specific Open Source Vulnerability (OSV)
            information.

        Returns
        -------
        List[ProjectRange]
            A list of ProjectRange objects representing the calculated ranges
            associated with the given OSV.

        Raises
        ------
        NotImplementedError
            This method must be implemented in a subclass. Calling this method
            directly on the base class will raise this exception.
        """
        raise NotImplementedError()
