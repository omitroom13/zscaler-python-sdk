import logging

from .defaults import ZiaApiBase


class Departments(ZiaApiBase):
    def list(self):
        """
        Gets a list of departments
        """
        path = "departments"
        return self._session.get(path)

    def show(self, department_id):
        """
        Gets the department for the specified ID
        """
        path = "departments/{}".format(department_id)
        return self._session.get(path)


class Groups(ZiaApiBase):
    def list(self):
        """
        Gets a list of groups
        """
        path = "groups"
        return self._session.get(path)

    def show(self, group_id):
        """
        Gets the group for the specified ID
        """
        path = "groups/{}".format(group_id)
        return self._session.get(path)


class Users(ZiaApiBase):
    def list(self):
        """
        Gets a list of all users and allows user filtering by name, department, or group
        """
        path = "users"
        return self._session.get(path)

    def show(self, user_id):
        """
        Gets the user information for the specified ID
        """
        path = "users/{}".format(user_id)
        return self._session.get(path)

    def create(self, user):
        """
        Adds a new user
        """
        path = "users"
        return self._session.post(path, user)

    def update(self, user_id, user):
        """
        Updates the user information for the specified ID
        """
        path = "users/{}".format(user_id)
        return self._session.put(path, user)

    def delete(self, user_object):
        """
        user_id : Deletes the user for the specified ID
        user_ids : Bulk delete users up to a maximum of 500 users per request
        """
        t = type(user_object)
        if t is int or t is str:
            path = "users/{}".format(user_object)
            return self._session.delete(path)
        elif t is dict:
            path = "users/bulkDelete"
            return self._session.post(path, user_object)
        raise RuntimeError('unknown user_object type {}'.format(t.__name__))


LOGGER = logging.getLogger(__name__)
