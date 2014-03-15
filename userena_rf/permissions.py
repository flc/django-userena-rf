from rest_framework import permissions


class IsNotAuthenticated(permissions.BasePermission):
    """
    Restrict access only to unauthenticated users.
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated():
            return False
        return True
