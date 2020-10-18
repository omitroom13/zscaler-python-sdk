import logging

from .defaults import ZiaApiBase


class SubLocations(ZiaApiBase):
    def list(self, location_id):
        """
        Gets the sub-location information for the location with the specified ID
        """
        path = 'locations/{}/sublocations'.format(location_id)
        return self._session.get(path)

    def create(self, sublocation):
        """
        Adds new sub-locations for the specified location_id
        """
        path = 'locations'
        if 'parentId' not in sublocation:
            raise RuntimeError('parentId required')
        return self._session.post(path, sublocation)


class Locations(ZiaApiBase):
    def __init__(self, _session):
        super().__init__(_session)
        self.sublocations = SubLocations(self._session)

    def list(self, summary=False):
        """
        Gets information on locations
        --summary : Gets a name and ID dictionary of locations
        """
        path = 'locations'
        if summary:
            path += '/lite'
        return self._session.get(path)

    def create(self, location):
        """
        Adds new locations
        """
        path = 'locations'
        return self._session.post(path, location)

    def show(self, location_id):
        """
        Gets the location information for the specified ID
        """
        if not location_id:
            return "Location Requried"
        path = 'locations/{}'.format(location_id)
        return self._session.get(path)

    def update(self, location_id, location):
        """
        Updates the location and sub-location information for the specified ID
        """
        path = 'locations/{}'.format(location_id)
        return self._session.put(path, location)

    def delete(self, location_object):
        """
        location_id : Deletes the location or sub-location for the specified ID
        location_ids : Bulk delete locations up to a maximum of 100 locations per request
        """
        t = type(location_object)
        if t is int or t is str:
            path = 'locations/{}'.format(location_object)
            return self._session.delete(path)
        elif t is dict:
            path = 'locations/bulkDelete'
            return self._session.post(path, location_object)
        raise RuntimeError(
            'unknown location_object type {}'.format(t.__name__))


LOGGER = logging.getLogger(__name__)
