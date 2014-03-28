# -*- encoding: utf8 -*-
#
# Copyright 2014 X-ion GmbH
# Author: Mouad Benchchaoui (m.benchchaoui@x-ion.de)
#
# All right reserved.

"""Keystone token backend using Redis: http://redis.io.

This token driver is similar to the memcached one except that because we
use Redis, stuff are more simpler and works better, including:

    1. Comparing to memcached revoked token doesn't go away as soon
       as we restart Redis, that's because Redis is a persistante data
       store and we also make sure that as soon as token is added to
       revocated list we call Redis save.
       Bug: https://bugs.launchpad.net/keystone/+bug/1182920

    2. Comparing to memcached which have a limit of the size of a key
       value (limit is the page size 1MB by default), Redis doesn't have
       one by default.
       Bug: https://bugs.launchpad.net/keystone/+bug/1242620

    3. There is also a limit per slab class in memcached which mean
       that we are allowed to save only a limited number of tokens
       for example with -m 64 MB -f 1.25 memcached options the slab
       class where pki token endup have a limit of around 3000 elements,
       and when this limit is hit memcached start evicting not recently
       used tokens to make place for new one, which mean that at some
       point user request start failing b/c token is not found (specially
       when using pki token with md5 e.g Horizon), Redis doesn't have a
       limit like this.

"""
from __future__ import absolute_import

import calendar
import copy
import datetime
import pickle

import redis

from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging
from keystone.openstack.common import timeutils
from keystone import token


CONF = config.CONF
LOG = logging.getLogger(__name__)


def _to_timestamp(dt):
    """Convert datetime.datetime(...) -> Interger (timestamp)."""
    return calendar.timegm(dt.timetuple())


# TODO (Mouad): Check if in IceHouse and using dogpile.cache Redis
# backend that this later will be better implementation or a similar
# one than this.
class Token(token.Driver):
    """Redis token driver.

    This class basically maintain/manupilate 2 type of records, string type
    for token data that are always set with an expiration date using Redis
    SETEX, and sorted set that are used to hold list of tokens per user, and
    a list of revoked tokens. For the sorted set we are implementing lazy
    entry expiration to expire tokens by setting each set element score to
    the timestamp of when it should expire and by using Redis ZREMRANGEBYSCORE.

    All data that is set in Redis are first pickled using Python Pickle module
    and when retrieved they are unpickled.

    """

    _revocation_list = 'keystone:token:revoked'

    def __init__(self):
        self._client = redis.from_url(CONF.redis.server)

    def _get_key(self, type_, key):
        return "keystone:%s:%s" % (type_, key)

    def _set(self, key, value, ttl):
        self._client.setex(
            key,
            pickle.dumps(value, pickle.HIGHEST_PROTOCOL),
            ttl)

    def _get(self, key):
        value = self._client.get(key)
        if value is not None:
            return pickle.loads(value)

    def _zadd(self, key, score, value):
        self._client.zadd(key, pickle.dumps(value), score)

    def _zrange(self, key, start, end):
        ret = self._client.zrange(key, start, end)
        return map(pickle.loads, ret)

    def _remove_expired(self, key):
        current_time = _to_timestamp(
            timeutils.normalize_time(timeutils.utcnow())
        )
        self._client.zremrangebyscore(
            key, 0, current_time)

    ### Driver.Token interface implementation start here. ###

    def get_token(self, token_id):
        """Return token data from Redis, If not found raise TokenNotFound.

        Redis Time Complexity: O(1)
        """
        if not token_id:
            raise exception.TokenNotFound(token_id='')

        ret = self._get(self._get_key('token', token_id))

        if not ret:
            raise exception.TokenNotFound(token_id=token_id)
        return ret

    def create_token(self, token_id, data):
        """Create a new Redis entry for new token.

        Redis Time Complexity: O(log(N)) with N number of user's token.
        """
        data = copy.deepcopy(data)

        expires = data.setdefault('expires', token.default_expire_time()) 
        current_time = timeutils.normalize_time(timeutils.utcnow())

        if not data.get('user_id'):
            data['user_id'] = data['user']['id']

        self._set(self._get_key('token', token_id), data,
                  expires - current_time)

        self._zadd(
            self._get_key('user', data.get('user_id')),
            _to_timestamp(expires),
            token_id)

        # Trust blabla blabla ... (Check memcached driver to know
        # what blabla mean).
        if CONF.trust.enabled and data.get('trust_id'):
            token_data = data['token_data']
            if data['token_version'] == token.provider.V2:
                trustee_user_id = token_data['access']['trust'][
                    'trustee_user_id']
            elif data['token_version'] == token.provider.V3:
                trustee_user_id = token_data['OS-TRUST:trust'][
                    'trustee_user_id']
            else:
                raise token.provider.UnsupportedTokenVersionException(
                    _('Unknown token version %s') %
                    data.get('token_version'))

            self._zadd(
                self._get_key('user', trustee_user_id),
                _to_timestamp(expires),
                token_id)

        return data

    def delete_token(self, token_id):
        """Delete token from Redis.

        Redis Time Complexity: O(log(N)) with N number of revokate not
        expired tokens.
        """
        data = self.get_token(token_id)

        self._client.delete(self._get_key('token', token_id))

        self._zadd(self._revocation_list, _to_timestamp(data['expires']), data)
        # Make sure that the revocation list is presisted by Redis.
        self._client.bgsave()

    def list_tokens(self, user_id, tenant_id=None, trust_id=None,
                    consumer_id=None):
        """List user tokens.

        Redis Time Complexity: O(log(N) + N) with N number of user's token
        not yet expired.
        """
        skey = self._get_key('user', user_id)
        self._remove_expired(skey)

        user_tokens = self._zrange(skey, 0, -1)

        tokens = []
        for token_id in user_tokens:
            token_data = self._get(self._get_key('token', token_id))

            if not token_data:
                continue

            if tenant_id and token_data.get('tenant_id') != tenant_id:
                continue

            if trust_id and token_data.get('trust_id') != trust_id:
                continue

            if consumer_id:
                try:
                    oauth = token_data['token_data']['token']['OS-OAUTH1']
                    if oauth.get('consumer_id') != consumer_id:
                        continue
                except KeyError:
                    continue

            tokens.append(token_id)

        return tokens

    def list_revoked_tokens(self):
        """Return all revokate not expired tokens.

        Redis Time Complexity: O(log(N) + N) with N number of revokate tokens
        not yet expired.
        """
        self._remove_expired(self._revocation_list)
        return self._zrange(self._revocation_list, 0, -1)
