# -*- coding: utf-8 -*-
from __future__ import absolute_import

import cherrypy

from . import ApiController, RESTController
from .. import mgr
from ..exceptions import DashboardException, UserAlreadyExists, \
    UserDoesNotExist
from ..security import Scope
from ..services.access_control import SYSTEM_ROLES, PasswordCheck
from ..services.auth import JwtManager

# minimum password complexity rules
def check_password_complexity(password, username, previous_password=None):
    check_password_complexity = PasswordCheck(password, username)
    if previous_password:
        if check_password_complexity.check_ifAsPreviousOne(previous_password):
            raise DashboardException(msg='Password is the same\
                                          as previous one.',
                                     code='not-strong-enough-password',
                                     component='Update/Create user')
    if check_password_complexity.check_ifContainsUsername():
        raise DashboardException(msg='Password is contains username,\
                                      which is forbidden.',
                                 code='not-strong-enough-password',
                                 component='Update/Create user')
    elif check_password_complexity.check_ifContainsForbiddenWords():
        raise DashboardException(msg='Password is contains keywords.',
                                 code='not-strong-enough-password',
                                 component='Update/Create user')
    elif check_password_complexity.check_ifRepetitiveCharacters():
        raise DashboardException(msg='Password contains repetitive\
                                      characters.',
                                 code='not-strong-enough-password',
                                 component='Update/Create user')
    elif check_password_complexity.check_ifSequentialCharacters():
        raise DashboardException(msg='Password contains sequential\
                                      characters.',
                                 code='not-strong-enough-password',
                                 component='Update/Create user')
    elif check_password_complexity.check_PasswordCharacters() < 10:
        raise DashboardException(msg='Password is too weak.',
                                 code='not-strong-enough-password',
                                 component='Update/Create user')

 
@ApiController('/user', Scope.USER)
class User(RESTController):
    @staticmethod
    def _user_to_dict(user):
        result = user.to_dict()
        del result['password']
        return result

    @staticmethod
    def _get_user_roles(roles):
        all_roles = dict(mgr.ACCESS_CTRL_DB.roles)
        all_roles.update(SYSTEM_ROLES)
        try:
            return [all_roles[rolename] for rolename in roles]
        except KeyError:
            raise DashboardException(msg='Role does not exist',
                                     code='role_does_not_exist',
                                     component='user')

    def list(self):
        users = mgr.ACCESS_CTRL_DB.users
        result = [User._user_to_dict(u) for _, u in users.items()]
        return result

    def get(self, username):
        try:
            user = mgr.ACCESS_CTRL_DB.get_user(username)
        except UserDoesNotExist:
            raise cherrypy.HTTPError(404)
        return User._user_to_dict(user)

    def create(self, username=None, password=None, name=None, email=None, roles=None):
        if not username:
            raise DashboardException(msg='Username is required',
                                     code='username_required',
                                     component='user')
        user_roles = None
        if roles:
            user_roles = User._get_user_roles(roles)
        try:
            if password:
                check_password_complexity(password, username)
            user = mgr.ACCESS_CTRL_DB.create_user(username, password, name, email)
        except UserAlreadyExists:
            raise DashboardException(msg='Username already exists',
                                     code='username_already_exists',
                                     component='user')
        if user_roles:
            user.set_roles(user_roles)
        mgr.ACCESS_CTRL_DB.save()
        return User._user_to_dict(user)

    def delete(self, username):
        session_username = JwtManager.get_username()
        if session_username == username:
            raise DashboardException(msg='Cannot delete current user',
                                     code='cannot_delete_current_user',
                                     component='user')
        try:
            mgr.ACCESS_CTRL_DB.delete_user(username)
        except UserDoesNotExist:
            raise cherrypy.HTTPError(404)
        mgr.ACCESS_CTRL_DB.save()

    def set(self, username, password=None, name=None, email=None, roles=None):
        try:
            user = mgr.ACCESS_CTRL_DB.get_user(username)
        except UserDoesNotExist:
            raise cherrypy.HTTPError(404)
        user_roles = []
        if roles:
            user_roles = User._get_user_roles(roles)
        if password:
            check_password_complexity(password, username, user.password)
            user.set_password(password)
        user.name = name
        user.email = email
        user.set_roles(user_roles)
        mgr.ACCESS_CTRL_DB.save()
        return User._user_to_dict(user)
