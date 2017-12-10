#!/bin/env python
from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import ObservedWatch
import sys


class FSEventHandler(PatternMatchingEventHandler):
    def __init__(self, patterns=None):
        PatternMatchingEventHandler.__init__(self, patterns)

    def on_created(self, event):
        print('CREATED: ' + str(event))

    # def on_modified(self, event):
    #     print('MODIFIED: ' + str(event))


class FileMonitor(object):
    def __init__(self):
        self.watches = []
        self.observer = Observer()
        self.observer.start()

    def add_watch(self, path, filename=None, recursive=False):
        print(str(path))
        print(str(filename))
        self.watches.append(self.observer.schedule(FSEventHandler(filename), path,
                                                   recursive))

    def remove_watch(self, path):
        for watch in self.watches:
            if watch.path == path:
                self.observer.unschedule(watch)

    def remove_all_watches(self):
        self.observer.unschedule_all()
