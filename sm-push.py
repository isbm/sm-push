#!/use/bin/python
#
# Author: Bo Maryniuk <bo@suse.de>
#
# The BSD 3-Clause License
# Copyright (c) 2013, SUSE Linux Products GmbH
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# * Neither the name of the SUSE Linux Products GmbH nor the names of its contributors may
#   be used to endorse or promote products derived from this software without
#   specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import os
import sys
import pty
import stat
import time
import socket
import random
import hashlib
import getpass
import tempfile
from xml.dom import minidom


class SMClientOutput:
    """
    Parse SM Client output.
    """
    SUCCESS = 'success'
    WARNING = 'warning'
    ERROR = 'failure'

    def __init__(self, output):
        """
        Get output from the SM Client.
        """
        self.events = {
            self.SUCCESS : [],
            self.WARNING : [],
            self.ERROR : [],
        }

        chop = False
        xmldoc = []
        for line in (output != None and output.strip() or "").split("\n"):
            if line.startswith('<?xml '):
                chop = True

            if chop:
                xmldoc.append(line.strip())

        xmldoc = minidom.parseString('\n'.join(xmldoc))
        for node in xmldoc.getElementsByTagName("message"):
            if not node.attributes or not node.attributes.get("type"):
                # Broken remote XML here. How to cry in a proper way?
                continue
            for cnode in node.childNodes:
                self.events[node.attributes.get("type") and node.attributes.get("type").value or "unknown"].append(cnode.nodeValue)



class SSH:
    """
    SSH tools wrapper.
    """

    def __init__(self, hostname, passwd, user, port, verbose=False):
        """
        Constructor.
        """
        self.hostname = hostname
        self.passwd = passwd
        self.user = user
        self.port = port
        self.verbose = verbose
        self.tunneling = []


    def set_tunneling(self, settings):
        """
        Set tunneling mode with settings of the following format:
        [(source_port, destination_port, hostname,),]
        """
        self.tunneling = []
        for src_port, dst_port, hostname in settings:
            self.tunneling.append("-R %s:%s:%s" % (src_port, hostname, dst_port))


    def _read(self, input):
        """
        Read the output of the child process.
        """
        out = ''
        try:
            out = os.read(input, 0x400)
            if self.verbose and str(out).strip():
                print >> sys.stderr, "INPUT>", out.strip()
        except Exception, e:
            # Always suppress IO fail here.
            pass

        return out


    def _results(self, pid, f):
        """
        Process output results.
        """
        out = ""
        while True:
            r = self._read(f)
            if r.lower().find("authenticity of host") > -1:
                os.write(f, 'yes\n')
                continue

            elif r.lower().find("password:") > -1:
                os.write(f, self.passwd + "\n")
                tmp = self._read(f)
                tmp += self._read(f)
                if tmp.lower().find("permission denied") > -1:
                    raise Exception("Invalid passwd")

            out += r
            if not len(r):
                break

        os.waitpid(pid, 0)
        os.close(f)

        return out.strip()


    def execute(self, c):
        """
        Execute one SSH command on the remote node.
        """
        (pid, f) = pty.fork()
        if pid == 0:
            cmd = ['ssh', '-o NumberOfPasswordPrompts=1', 
                   '-p %s' % self.port, self.user + '@' + self.hostname, c,]
            os.execlp("ssh", *(cmd[:1] + self.tunneling + cmd[1:]))
        else:
            return self._results(pid, f)


    def push_file(self, src, dst):
        """
        Copy source file to the destination on the remote host.
        """
        pid, f = pty.fork()
        if pid == 0:
            os.execlp("scp", "scp", '-o NumberOfPasswordPrompts=1', 
                      '-P %s' % self.port, src, self.user + '@' + self.hostname + ':' + dst)
        else:
            return self._results(pid, f)


    def deploy_identity(self):
        """
        Deploy SSH identity on the remote node.
        """
        idpath = "%s/.ssh/id_rsa.pub" % os.path.expanduser('~' + getpass.getuser())

        if self.verbose:
            print >> sys.stderr, "Deploying SSH key %s" % idpath

        self.execute("umask 077; test -d .ssh || mkdir .ssh;")

        # Make temp name
        digest = hashlib.md5()
        block = 0x10000
        fh = open(idpath)
        buff = fh.read(block)
        while len(buff) > 0:
            digest.update(buff)
            buff = fh.read(block)
        fh.close()
        destfile = '.id-rsa-pub.%s.%s' % (self.hostname, digest.hexdigest())

        # Add public key and cleanup
        pid, f = pty.fork()
        if pid == 0:
            os.execlp("scp", "scp", '-o NumberOfPasswordPrompts=1', 
                      '-P %d' % self.port, idpath, self.user + '@' + self.hostname + ':' + destfile)
        else:
            self._results(pid, f)
        self.execute("umask 077; cat %s >> .ssh/authorized_keys; rm %s" % (destfile, destfile))



class PushEnvironment:
    """
    Class to setup push environment: SSH, keys etc.
    """
    def __init__(self, target_host, params, target_port=22):
        self.target_host = target_host
        self.target_port = target_port
        self.target_os = 'Unknown'
        self.target_arch = 'Unknown'
        self.params = params


    def setup(self):
        """
        Prepare push environment on the server side.
        """
        # SSH keys around?
        key_fp = self.verify_id_rsa()
        if key_fp and not 'quiet' in self.params.keys():
            RuntimeUtils.info('New RSA key for SSH generated.')
            RuntimeUtils.info('Fingerprint: ' + key_fp)

        # Public keys on target?
        target_machine = self.verify_keychain()
        if not target_machine:
            if not 'quiet' in self.params.keys():
                RuntimeUtils.info('No public key deployed on target machine.')
            else:
                raise Exception("You want it quiet, but I need remote password for \"%s\"!" % getpass.getuser())
            self.deploy_keychain()
            target_machine = self.verify_keychain()

        target_machine = filter(None, target_machine.split(' '))
        if len(target_machine) == 2:
            self.target_os, self.target_arch = target_machine
        else:
            raise Exception("Unknown platform: " + self.target_os)

        if not 'quiet' in self.params.keys():
            RuntimeUtils.info('Target machine "%s" prepared.' % self.target_host)


    def deploy_keychain(self):
        """
        Deploy public key on the target machine.
        Require console password input.
        """
        if not os.environ.get('SSH_REMOTE_PASSWORD'):
            print >> sys.stdout, "REQUEST:\t",
            sys.stdout.flush()
        msg = "Enter login password to %s\n\t\tas user '%s': " % (self.target_host, getpass.getuser())
        SSH(self.target_host, os.environ.get('SSH_REMOTE_PASSWORD') or getpass.getpass(msg),
            user=getpass.getuser(), port=self.target_port).deploy_identity()


    def verify_keychain(self):
        """
        Verify SSH keys are deployed on the target machine.
        """
        cin, out, err = os.popen3("/usr/bin/ssh -oBatchMode=yes %s uname -sp" % self.target_host)
        try:
            return (out.read() + '').strip()
        except Exception, ex:
            out = None


    def verify_id_rsa(self):
        """
        Get the id_rsa.pub SSH key in place, generate new if none.
        """
        key_fp = None
        id_path = os.path.expanduser("~%s/.ssh/id_rsa" % getpass.getuser())
        if not os.path.exists("%s.pub" % id_path):
            for line in os.popen("/usr/bin/ssh-keygen -t rsa -N '' -f %s" % id_path).readlines():
                tokens = line.split(' ')
                if len(tokens) == 2 and tokens[-1].startswith(getpass.getuser() + "@"):
                    key_fp = tokens[0].upper()

        return key_fp



class TunnelConfig:
    """
    Class to configure tunneling.
    """
    # Ports, used by default, if no config around
    CFG_DEFAULT_HTTP_PORT=1232
    CFG_DEFAULT_HTTPS_PORT=1233
    
    # What to look in configs
    CFG_HTTP_PORT_KEY="server_push_port_http"
    CFG_HTTPS_PORT_KEY="server_push_port_https"

    # Where to look in configs
    PTH_RHN_CONF="/etc/rhn/rhn.conf"
    PTH_RHN_DEFAULTS="/usr/share/rhn/config-defaults/rhn_web.conf"


    def __init__(self):
        """
        Init and setup the tunneling.
        """
        cfg = self.get_config(self.PTH_RHN_DEFAULTS)   # Get defaults (if any)
        cfg.update(self.get_config(self.PTH_RHN_CONF)) # Apply custom conf on top

        self.http_port = cfg.get(self.CFG_HTTP_PORT_KEY, self.CFG_DEFAULT_HTTP_PORT)
        self.https_port = cfg.get(self.CFG_HTTPS_PORT_KEY, self.CFG_DEFAULT_HTTPS_PORT)


    def get_config(self, config):
        """
        Parse typical key=value config 
        and return a dictionary of parsed values back.
        """
        cfg = {}
        for conf_item in open(config).readlines():
            if conf_item.find('=') > -1 and not conf_item.strip().startswith('#'):
                cfg.update(dict([map(lambda i:i.strip(), conf_item.split('=', 1))]))

        return cfg



class TaskPush:
    """
    Class to perform the tasks on the remote host.
    """
    def __init__(self, params):
        self.host_ip, self.hostname = self._get_hostname(params.get('hostname', None))
        self.localhost_ip, self.localhostname = self._get_hostname(socket.gethostname())
        self.params = params
        self.ssh = None
        self.environ = None
        self.tunnel = None
        self.is_tunnel_enabled = None


    def _get_hostname(self, hostname):
        """
        Resolve to fully qualified hostname.
        """
        if not hostname:
            raise Exception("Unknown target hostname.")
        host_ip = None
        fullname = None
        try:
            host_ip = socket.gethostbyname(hostname)
            fullname = socket.gethostbyaddr(host_ip)[0]
        except Exception, ex:
            raise Exception("Unable to resolve \"%s\" hostname." % hostname)

        return host_ip, fullname


    def prepare(self):
        """
        Prepare the push mechanism.
        """
        self.environ = PushEnvironment(self.hostname, self.params)
        self.environ.setup()

        self.tunnel = TunnelConfig()
        self.ssh = SSH(self.hostname, None, user=getpass.getuser(), port=self.params.get('ssh-port', '22'))


    def perform(self):
        """
        Run the task on the target system.
        """
        # Enable or disable tunneling
        if 'tunneling' in self.params.keys():
            if self.params.get('tunneling') in ['yes', 'no']:
                self._do_tunneling()
            else:
                raise Exception('What means "%s" in context of tunneling?' % self.params.get('tunneling'))
        else:
            # Check if tunneling is on the remote, since user is not asking for it.
            if self.is_tunnel_enabled == None:
                self._do_tunneling(check_only=True)
            if 'quiet' not in self.params.keys():
                RuntimeUtils.info("Tunnel is %s." % (self.is_tunnel_enabled and 'enabled' or 'disabled'))

        # Register, if requested
        if 'activation-keys' in self.params.keys():
            self._do_register_at_sm(force=('override' in self.params.keys()))
        

        # Execute some command, if any
        if self.params.get('command'):
            self._do_command()



    # Performing tasks
    def _do_register_at_sm(self, force=False):
        """
        Register remote node at SUSE Manager.
        """
        ssl_certificate = "/srv/www/htdocs/pub/RHN-ORG-TRUSTED-SSL-CERT" # Point of configuration in a future.
        if self.environ.target_os.lower() == 'linux':
            # Register remote against SUSE Manager
            if self.ssh.execute("rpm -qa | grep sm-client-tools || echo 'absent'") == 'absent':
                RuntimeUtils.info('Installing SM Client on target machine')
                remote_pkg_pth = '/tmp/sm-client-tools.%s.%s.rpm' % (time.time(), random.randint(0xff, 0xffff)) # Temporary unique (hopefully) name on remote filesystem.
                local_pkg_pth = "/srv/www/htdocs/pub/bootstrap/sm-client-tools.rpm"
                if not os.path.exists(local_pkg_pth):
                    raise Exception('SUSE Manager Client package does not exists.')
                self.ssh.push_file(local_pkg_pth, remote_pkg_pth)
                self.ssh.execute('/bin/rpm -ivh %s; rm %s' % (remote_pkg_pth, remote_pkg_pth))
                if self.ssh.execute('test -e /usr/bin/sm-client && echo "installed" || echo "failed"') == 'failed':
                    raise Exception("SM Client installation failed. :-(")
                else:
                    if 'quiet' not in self.params.keys():
                        RuntimeUtils.info("SM Client has been installed")
            else:
                if 'quiet' not in self.params.keys():
                    RuntimeUtils.info('SM Client is already installed')

            # Get SSL certificate fingerprint
            ssl_fp = os.popen("/usr/bin/openssl x509 -noout -in %s -fingerprint" % ssl_certificate).read().split('=')[-1].strip()
            if not 'quiet' in self.params.keys():
                RuntimeUtils.info("SSL certificate: %s" % ssl_fp)

            # If we need sudo, we need to know it is there and we have right permissions
            if getpass.getuser() != 'root':
                if self.ssh.execute("test -e /usr/bin/sudo && echo 'OK'") != 'OK':
                    raise Exception("You cannot run anything on \"%s\" as \"%s\" without sudo installed!" % (self.hostname, getpass.getuser()))
                if self.ssh.execute("/usr/bin/sudo -S true < /dev/null &>/dev/null && echo 'OK'") != 'OK':
                    raise Exception("Not enough privileges for user \"%s\" on \"%s\" node." % (getpass.getuser(), self.hostname))

            # Register machine
            remote_tmp_logfile = '/tmp/.sm-client-tools.%s.%s.log' % (time.strftime('%Y%m%d.%H%M%S.backup', time.localtime()), random.randint(0xff, 0xffff))
            overrides = []
            if self.is_tunnel_enabled:
                overrides.append('--cfg=noSSLServerURL,http://%s:%s/' % (self.localhostname, self.tunnel.http_port))
                overrides.append('--cfg=serverURL,https://%s:%s/XMLRPC' % (self.localhostname, self.tunnel.https_port))
            self.ssh.execute("/usr/bin/sudo -n /usr/bin/sm-client --output-format=xml --hostname=%s --activation-keys=%s --ssl-fingerprint=%s %s > %s" %
                             (self.localhostname, self.params['activation-keys'], ssl_fp, ' '.join(overrides), remote_tmp_logfile))
            smc_out = SMClientOutput(self.ssh.execute("test -e %s && /bin/cat %s && rm %s || echo '<?xml version=\"1.0\" encoding=\"UTF-8\"?><log/>'" % 
                                                      (remote_tmp_logfile, remote_tmp_logfile, remote_tmp_logfile)))
            if smc_out.events.get(SMClientOutput.ERROR):
                RuntimeUtils.warning("Remote machine was not happy:")
                for error_message in smc_out.events.get(SMClientOutput.ERROR):
                    RuntimeUtils.error(error_message)
                raise Exception("Registration failed. Please login to the %s and find out why." % self.hostname)
            elif smc_out.events.get(SMClientOutput.WARNING) and not 'quiet' in self.params.keys():
                for warning_message in smc_out.events.get(SMClientOutput.WARNING):
                    RuntimeUtils.warning(self.hostname + ": " + warning_message)
            # No success blah-blah-blah here.
        else:
            # Solaris fans, do it yourself. :-)
            raise Exception('I cannot register %s against SUSE Manager as of today.')

        if 'quiet' not in self.params.keys():
            RuntimeUtils.info("Remote machine %s has been registered successfully." % self.hostname)


    def _do_tunneling(self, check_only=False):
        """
        Enable or disable tunnel.
        """
        if not self.ssh:
            raise Exception("SSH link was not initialized.")

        # Get content of the /etc/hosts on the remote machine
        random.seed()
        token = '# __%s.%s__' % (time.time(), random.randint(0xff, 0xffff))
        etc_hosts = self.ssh.execute("test -e /etc/hosts && cat /etc/hosts || echo '%s'" % token) + ""

        self.is_tunnel_enabled = False
        if etc_hosts.find(token) > -1:
            raise Exception('Tunneling cannot be enabled on this system.')
        else:
            for line in map(lambda item:item.strip().lower(), etc_hosts.split("\n")):
                if not line.startswith('#') and line.find(self.localhostname) > -1:
                    self.is_tunnel_enabled = True
                    break

        # Setup SSH if tunneling around
        if self.is_tunnel_enabled:
            self.ssh.set_tunneling(((self.tunnel.http_port, 80, self.localhostname),
                                    (self.tunnel.https_port, 443, self.localhostname),))

        # Exit if this is only check/setup
        if check_only:
            return

        # Skip procedure if nothing needed to do.
        enable = self.params.get('tunneling', '') == 'yes'
        RuntimeUtils.info('%s tunneling on %s node.' % ((enable and 'Enabling' or 'Disabling'), self.hostname))
        if enable:
            if self.is_tunnel_enabled:
                RuntimeUtils.warning('Tunelling on the node "%s" is already enabled.' % self.hostname)
                return
        else:
            if not self.is_tunnel_enabled:
                RuntimeUtils.warning('Tunelling on the node "%s" is already disabled.' % self.hostname)
                return
        self.is_tunnel_enabled = enable
        hosts = []
        for line in etc_hosts.split("\n"):
            if not line.strip().startswith('#'):
                if enable and line.lower().find('localhost') + 1:
                    line = map(lambda item:item.strip(), filter(None, line.split(' ')))
                    line.append(self.localhostname)
                    line = ' '.join(line)
                else:
                    line = ' '.join(filter(None, line.replace(self.localhostname, '').split(' '))).strip()
            hosts.append(line)
        etc_hosts = '\n'.join(hosts)

        # Save to tempfile
        tmpfd, tmppth = tempfile.mkstemp(prefix='sm-push-hosts-%s-' % self.hostname)
        tmpfh = os.fdopen(tmpfd, "w")
        tmpfh.write(etc_hosts + "\n")
        tmpfh.close()

        # Push the file to the remote
        remote_hosts_pth = '/tmp/.sm-push-hosts-%s.%s' % (time.time(), random.randint(0xff, 0xffff))
        self.ssh.push_file(tmppth, remote_hosts_pth)

        # Push failed?
        if (self.ssh.execute("test -e %s && echo 'OK' || echo '%s'" % (remote_hosts_pth, token)) + "").strip() != 'OK':
            raise Exception('Unable to send new configuration to "%s" node.' % self.hostname)

        # Replace remote file
        if 'safe' in self.params.keys():
            backup_suffix = time.strftime('%Y%m%d.%H%M%S.backup', time.localtime())
            res = self.ssh.execute('mv /etc/hosts /etc/hosts.%s' % backup_suffix)
            if res:
                RuntimeUtils.error(res)
                self._cleanup(tmppth)
                raise Exception('Remote node error.')
            if not 'quiet' in self.params.keys():
                RuntimeUtils.info('Previous file "/etc/hosts" has been saved as "/etc/hosts.%s"' % backup_suffix)
        res = self.ssh.execute('mv %s /etc/hosts; chmod 0644 /etc/hosts' % remote_hosts_pth)
        if res:
            RuntimeUtils.error(res)
            self._cleanup(tmppth)
            raise Exception('Remote node error.')

        # Restart DNS cache
        self._restart_dns_cache()

        # Enable or disable 3rd party services
        self._enable_services(not enable)


    def _enable_services(self, enable):
        """
        Enable or disable various 3rd party services that should not run when SSH tunneling is around.
        """
        if self.environ.target_os.lower() == 'linux':
            for service_name, service_exec in [('OSAD client-side', '/etc/init.d/osad'),
                                               ('Red Hat Network update query', '/etc/init.d/rhnsd'),]:
                if self.ssh.execute('test -e %s && %s %s || echo "absent"' %(service_exec, service_exec, (enable and 'start' or 'stop'))) != 'absent':
                    RuntimeUtils.info('%s %s service' % ((enable and 'Enabling' or 'Stopping'), service_name))
        else:
            RuntimeUtils.warning('Additional service operations are not supported for %s on %s.' % (self.environ.target_os, self.environ.target_arch))
            

    def _restart_dns_cache(self):
        """
        Restart DNS cache.
        On Linux it is nscd.
        """
        if self.environ.target_os.lower() == 'linux':
            if self.ssh.execute("test -e /etc/init.d/nscd && echo 'exists' || echo 'absent'") == 'exists':
                RuntimeUtils.info('Restarting name service cache daemon on remote node.')
                self.ssh.execute('/etc/init.d/nscd')
        else:
            RuntimeUtils.warning('DNS cache operations are not supported for %s on %s.' % (self.environ.target_os, self.environ.target_arch))


    def _cleanup(self, *fpth):
        """
        Cleanup all given file paths.
        """
        for fp in fpth:
            if os.path.exists(fp):
                try:
                    os.unlink(fp)
                except Exception, ex:
                    RuntimeUtils.warning('Could not remove local temporary file "%s"' % fp)
                    RuntimeUtils.error(str(ex))


    def _do_command(self):
        """
        Execute a custom command on the remote machine.
        """
        if not self.ssh:
            raise Exception("SSH link was not initialized.")

        if not 'quiet' in self.params.keys():
            RuntimeUtils.info('Executing command: "' + self.params.get('command') + '"')
            RuntimeUtils.info('Remote response below as follows:')
        response = self.ssh.execute(self.params.get('command'))

        # Output "frame" only during verbose mode (default)
        if not 'quiet' in self.params.keys():
            print >> sys.stdout, "-" * 80
        print >> sys.stdout, response
        if not 'quiet' in self.params.keys():
            print >> sys.stdout, "-" * 80


class RuntimeUtils:
    """
    All 'orphan' functions are here. :)
    """
    @classmethod
    def is_root(self):
        """
        Returns True if user is root.
        """
        return getpass.getuser() == 'root'


    @classmethod
    def header(self):
        """
        Displays header.
        """
        print >> sys.stdout, "SUSE Manager Task Push. Version 0.1\n" \
        + "Copyright (c) 2013 by SUSE Linux Products GmbH\n"


    @classmethod
    def usage(self):
        """
        Displays usage and exits.
        """
        print >> sys.stderr, "Usage:\n\tsm-push <options>\n"
        print >> sys.stderr, "Options:"
        print >> sys.stderr, "\t--hostname=<DNS name>\t\tSpecify target hostname."
        print >> sys.stderr, "\t--activation-keys=<list>\tComma separated list of activation keys.\n" \
            + "\t\t\t\t\tIf parameter specified, machine will be registered against SUSE Manager."
        print >> sys.stderr, "\t--override\t\t\tIgnore conditional request of an operation and always perform it."
        print >> sys.stderr, "\t--command=\"<command>\"\t\tCustom command to be executed on the target machine.\n" \
            + "\t\t\t\t\tPlease escape quote and/or double-quote inside, if required."
        print >> sys.stderr, "\t--tunneling=<yes|no>\t\tEnable or disable tunneling."
        print >> sys.stderr, "\t--safe\t\t\t\tMake a backup copy of previous configuration."
        print >> sys.stderr, "\t--quiet\t\t\t\tProduce no output at all except occurred errors and command result.\n"
        print >> sys.stderr, "\t--help\t\t\t\tDisplays this message.\n\n"
        print >> sys.stderr, "Environment variables:"
        print >> sys.stderr, "\tSSH_REMOTE_PASSWORD\t\tPassword on the remote machine to the calling user.\n"

        sys.exit(1)


    @classmethod
    def error(self, error_message):
        """
        Display an error message.
        """
        if error_message:
            print >> sys.stderr, "Error:\n\t%s\n" % error_message

        sys.exit(1)


    @classmethod
    def info(self, msg, output=sys.stdout):
        print >> output, "INFO:\t\t%s" % msg
        output.flush()


    @classmethod
    def warning(self, msg, output=sys.stdout):
        print >> output, "WARNING:\t%s" % msg
        output.flush()


    @classmethod
    def required_params(self):
        """
        Returns True or False if required params has been passed.
        """
        params = RuntimeUtils.get_params()
        if 'hostname' in params.keys():
            for p in ['activation-keys', 'command', 'tunneling']:
                if p in params.keys():
                    return True


    @classmethod
    def error(self, msg, output=sys.stdout):
        print >> output, "ERROR:\t\t%s" % msg
        output.flush()


    @classmethod
    def get_params(self):
        """
        Parse params.
        """
        params = {}
        for arg in sys.argv[1:]:
            if arg[:2] != '--':
                continue

            if arg in ['--help', '--override', '--quiet', '--safe']:
                params[arg[2:]] = None
            elif arg.find("=") > -1:
                k, v = arg.split("=", 1)
                params[k[2:]] = v

        return params


# Main app
if __name__ == "__main__":
    params = RuntimeUtils.get_params()
    if not RuntimeUtils.required_params() or 'help' in params.keys():
        RuntimeUtils.header()
        RuntimeUtils.usage()
    else:
        try:
            task_push = TaskPush(params)
            task_push.prepare()
            task_push.perform()
        except Exception, ex:
            RuntimeUtils.error(str(ex))

