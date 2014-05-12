# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy
import datetime
import uuid

import memcache

from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone.openstack.common import timeutils
from keystone import tests
from keystone.tests import test_backend
from keystone.token.backends import memcache as token_memcache

CONF = config.CONF


class MemcacheClient(object):
    """Replicates a tiny subset of memcached client interface."""

    def __init__(self, *args, **kwargs):
        """Ignores the passed in args."""
        self.cache = {}
        self.reject_cas = False

    def add(self, key, value):
        if self.get(key):
            return False
        return self.set(key, value)

    def append(self, key, value):
        existing_value = self.get(key)
        if existing_value:
            self.set(key, existing_value + value)
            return True
        return False

    def check_key(self, key):
        if not isinstance(key, str):
            raise memcache.Client.MemcachedStringEncodingError()

    def gets(self, key):
        #Call self.get() since we don't really do 'cas' here.
        return self.get(key)

    def get(self, key):
        """Retrieves the value for a key or None."""
        self.check_key(key)
        obj = self.cache.get(key)
        now = utils.unixtime(timeutils.utcnow())
        if obj and (obj[1] == 0 or obj[1] > now):
            # NOTE(morganfainberg): This behaves more like memcache
            # actually does and prevents modification of the passed in
            # reference from affecting the cached back-end data. This makes
            # tests a little easier to write.
            #
            # The back-end store should only change with an explicit
            # set/delete/append/etc
            data_copy = copy.deepcopy(obj[0])
            return data_copy

    def set(self, key, value, time=0):
        """Sets the value for a key."""
        self.check_key(key)
            # NOTE(morganfainberg): This behaves more like memcache
            # actually does and prevents modification of the passed in
            # reference from affecting the cached back-end data. This makes
            # tests a little easier to write.
            #
            # The back-end store should only change with an explicit
            # set/delete/append/etc
        data_copy = copy.deepcopy(value)
        self.cache[key] = (data_copy, time)
        return True

    def cas(self, key, value, time=0, min_compress_len=0):
        # Call self.set() since we don't really do 'cas' here.
        if self.reject_cas:
            return False
        return self.set(key, value, time=time)

    def reset_cas(self):
        #This is a stub for the memcache client reset_cas function.
        pass

    def delete(self, key):
        self.check_key(key)
        try:
            del self.cache[key]
        except KeyError:
            #NOTE(bcwaldon): python-memcached always returns the same value
            pass


class MemcacheToken(test_backend.KVSToken, tests.TestCase):

    def setUp(self):
        super(MemcacheToken, self).setUp()
        self.token_man.driver = token_memcache.Token(client=MemcacheClient())

    def test_cleanup_user_index_on_create(self):
        valid_token_id = uuid.uuid4().hex
        second_valid_token_id = uuid.uuid4().hex
        expired_token_id = uuid.uuid4().hex
        user_id = unicode(uuid.uuid4().hex)

        expire_delta = datetime.timedelta(seconds=86400)

        valid_data = {'id': valid_token_id, 'a': 'b',
                      'user': {'id': user_id}}
        second_valid_data = {'id': second_valid_token_id, 'a': 'b',
                             'user': {'id': user_id}}
        expired_data = {'id': expired_token_id, 'a': 'b',
                        'user': {'id': user_id}}
        self.token_api.create_token(valid_token_id, valid_data)
        self.token_api.create_token(expired_token_id, expired_data)
        # NOTE(morganfainberg): Directly access the data cache since we need to
        # get expired tokens as well as valid tokens. token_api.list_tokens()
        # will not return any expired tokens in the list.
        user_key = self.token_api.driver._prefix_user_id(user_id)
        user_token_list = self.token_api.driver.client.get(user_key)
        self.assertEqual(len(user_token_list), 2)
        # user_token_list is a list of (token, expiry) tuples
        expired_idx = [i[0] for i in user_token_list].index(expired_token_id)
        # set the token as expired.
        user_token_list[expired_idx] = (user_token_list[expired_idx][0],
                                        timeutils.utcnow() - expire_delta)
        self.token_api.driver.client.set(user_key, user_token_list)

        self.token_api.create_token(second_valid_token_id, second_valid_data)
        user_token_list = self.token_api.driver.client.get(user_key)
        self.assertEqual(len(user_token_list), 2)

    def test_convert_token_list_from_json(self):
        token_list = ','.join(['"%s"' % uuid.uuid4().hex for x in xrange(5)])
        token_list_loaded = jsonutils.loads('[%s]' % token_list)
        converted_list = self.token_api.driver._convert_user_index_from_json(
            token_list, 'test-key')
        for idx, item in enumerate(converted_list):
            token_id, expiry = item
            self.assertEqual(token_id, token_list_loaded[idx])
            self.assertIsInstance(expiry, datetime.datetime)

    def test_convert_token_list_from_json_non_string(self):
        token_list = self.token_api.driver._convert_user_index_from_json(
            None, 'test-key')
        self.assertEqual([], token_list)

    def test_convert_token_list_from_json_invalid_json(self):
        token_list = self.token_api.driver._convert_user_index_from_json(
            'invalid_json_list', 'test-key')
        self.assertEqual([], token_list)

    def test_cas_failure(self):
        expire_delta = datetime.timedelta(seconds=86400)
        self.token_api.driver.client.reject_cas = True
        token_id = uuid.uuid4().hex
        user_id = unicode(uuid.uuid4().hex)
        token_data = {'expires': timeutils.utcnow() + expire_delta,
                      'id': token_id}
        user_key = self.token_api.driver._prefix_user_id(user_id)
        self.assertRaises(
            exception.UnexpectedError,
            self.token_api.driver._update_user_list_with_cas,
            user_key, token_id, token_data)


class MemcacheTokenCacheInvalidation(test_backend.KVSTokenCacheInvalidation,
                                     tests.TestCase):

    def setUp(self):
        super(MemcacheTokenCacheInvalidation, self).setUp()
        CONF.token.driver = 'keystone.token.backends.memcache.Token'
        self.token_man.driver = token_memcache.Token(client=MemcacheClient())
        self._create_test_data()
