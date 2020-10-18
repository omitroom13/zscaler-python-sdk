from .defaults import ZiaApiBase


class AdminRoleManagement(ZiaApiBase):
    def list_roles(self):
        """
        Gets a name and ID dictionary of all admin roles
        """
        path = 'adminRoles/lite'
        return self._session.get(path)

    def list(self):
        """
        Gets a list of admin users
        """
        path = 'adminUsers'
        return self._session.get(path)

    def create(self, admin):
        """
        Creates an admin or auditor user
        """
        path = 'adminUsers'
        return self._session.post(path, admin)

    def update(self, user_id, admin):
        """
        Updates an admin or auditor user for the specified ID
        """
        path = 'adminUsers/{}'.format(user_id)
        return self._session.put(path, admin)

    def delete(self, user_id):
        """
        Deletes an admin or auditor user for the specified ID
        """
        path = 'adminUsers/{}'.format(user_id)
        return self._session.delete(path)
