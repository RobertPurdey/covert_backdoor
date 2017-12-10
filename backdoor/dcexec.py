import subprocess
import os
from bdfilemon import FileMonitor

class Executor(object):
    def __init__(self):
        self.proc = None
        self.working_directory = os.path.dirname(os.path.realpath(__file__))
        self.filemon = FileMonitor()

    def add_watches(self, path_list):
        for path in path_list:
            self.add_watch(path)

    def add_watch(self, path):
        try:
            directory, filename = path.split(' ')
        except ValueError:
            directory = path
            filename = None

        self.filemon.add_watch(directory, filename=filename)

    def run(self, command):
        """
        Executes the given command in a shell and returns the command output.
        """

        # cd is a special case. The subprocess cannot change the working directory of our process, 
        # so we have to do it manually
        if command[:3] == 'cd ':
            try:
                os.chdir(os.path.expanduser(command[3:]))
            except OSError as e:
                return None, str(e)

            return None, None
        if command[:7] == 'UPLOAD ':
            #
            pass
        if command[:9] == 'DOWNLOAD ':
            # get the remaining string in the command as the file to send back
            # if the file does not exist return an error message in stderr
            # otherwise, return the file's contents in stdout
            pass
        if command[:6] == 'WATCH ':
            # add a watch
            self.add_watch(command[6:])
        else:
            self.proc = subprocess.Popen([str(command)], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, shell=True)
            return self.proc.communicate()
