# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 X-ion GmbH
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

"""Unit test cases for redis token backend."""

import fakeredis

from keystone import config
from keystone import tests
from keystone.tests import test_backend
from keystone.token.backends import redis as token_redis


CONF = config.CONF


class RedisToken(test_backend.KVSToken, tests.TestCase):

    def setUp(self):
        super(RedisToken, self).setUp()
        fakeredis.DATABASES.clear()
        self.token_man.driver = token_redis.Token(
            client=fakeredis.FakeStrictRedis())


class RedisTokenCacheInvalidation(test_backend.KVSTokenCacheInvalidation,
                                  tests.TestCase):

    def setUp(self):
        super(RedisTokenCacheInvalidation, self).setUp()
        CONF.token.driver = 'keystone.token.backends.redis.Token'
        fakeredis.DATABASES.clear()
        self.token_man.driver = token_redis.Token(
            client=fakeredis.FakeStrictRedis())
        self._create_test_data()
