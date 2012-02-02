#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from gevent.pywsgi import WSGIServer
from cgi import parse_qs
import hashlib
import time
import logging
from random import randint
from pprint import pprint

# Logging
logger = logging.getLogger('CAT')
hdlr = logging.FileHandler('cat-tracker.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

# Holds all the peers. If server is booted *POF* ALL DATA GONE.
peers = {}

# Announce interval in seconds.
interval = 60

# For generating an ID for each peer
def get_hash(id, hash):
    return hashlib.sha1("%s%s"%(id, hash)).hexdigest()
    
# Stupid validation function.
def validate(what, value, max_chars=False):
    retval = False

    if value == None or value == False or len(value) <= 1:
        return u'Argument %s is missing.' % what

    if len(value) > 128:
        return u'Argument %s is too large to handle' % what

# Main function for tracking
def track(peers, peer_hash = False, interval=60, min_interval=30):
    p = ''
    c = i = 0
    logger.info("Peer asking list of %s" % peer_hash)

    # For peer in list.
    for d in peers:
        d=peers[d]
        
        # Complete (c) or incomplete (i), seed/leech.
        if (d[7]):
            c+=1
            continue # Seeders should NOT be allowed to see each other
            logger.info("Found: Seeder. IP: %s ID: %s" %(d[0], d[1]))
        else:
            logger.info("Found: Incomplete IP: %s ID: %s" %(d[0], d[1]))
            i+=1 # Ok, not seeding.

        # Bencode
        pid = u'7:peer id%s:%s' % (len(d[1]),d[1],)

        p = p + u'd2:ip%s:%s%s4:porti%see' % \
                 (len(d[0]), d[0], pid,d[2])
    
    r = u'd8:intervali%se12:min intervali%s' % (interval, min_interval,)
    r = r + u'e8:completei%se10:incompletei%se5:peersl%see' % \
              (c,i,p)
        
    return r


# Gevent pywsgi
def application(environ, start_response):

    if 'QUERY_STRING' in environ:
        qs = parse_qs(environ['QUERY_STRING'])
    else:
        qs = False

    status = '200 OK'
    body = u''
       
    headers = [
        ('Content-Type', 'text/html')
    ]
    
    if 'PATH_INFO' in environ:
        request_path = environ['PATH_INFO'].strip('/')
    else:
        request_path = u''


    if request_path in ['announce', '']:
        # Initializing default
        seeder = False
        left = 0
        peer_port = False
        info_hash = u''
        key = u''
        event = u'Unknown'
        peer_ip = environ['REMOTE_ADDR']
        peer_client = u''
        peer_id = False

        # Get client user-agent if supplied.
        if 'HTTP_USER_AGENT' in environ:
            peer_client = environ['HTTP_USER_AGENT']

        
        if 'left' in qs:
            left = int(qs['left'][0])
            if left < 1: seeder = True
        
        if 'info_hash' in qs:
            info_hash = qs['info_hash'][0]
        
        if 'peer_port' in qs:
            peer_port = qs['port'][0]

        if 'peer_id' in qs:
            peer_id = qs['peer_id'][0]

        if 'key' in qs:
            key = qs['key'][0]

        if 'event' in qs:
            event = qs['event'][0]

        # Validation
        body = validate('info_hash', info_hash)
        body = validate('peer_id', peer_id)
        body = validate('key', key)
        
        timestamp = int(time.time())
        expire = timestamp+interval+randint(0,12)
        
        peer_hash = get_hash(peer_id, info_hash)

        if event == 'stopped':
            try: del[peer_hash]
            except: pass
            body = track([])
        
        if peer_hash in peers:
            if peers[peer_hash][6] != key:
                body = 'Bruteforcing'

        if not body:
            new_peer = (peer_ip, peer_id, peer_port, expire, info_hash,
                        peer_client, key, seeder)
            peers[peer_hash] = new_peer 
            body = track(peers, peer_hash)


    start_response(status, headers)
    return [body]

WSGIServer(('', 8000), application).serve_forever()


