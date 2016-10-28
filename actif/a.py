import subprocess

def execute():
    flag = "FLAG-"
    for i in range(1, 256):
        ip = '192.168.1.' + str(i)
        result = subprocess.call('ping' + ' -n ' +'1 ' + ip, stdout=subprocess.PIPE)
        if result == 0 and ip != '192.168.1.200' and ip != '192.168.1.201':
            flag += str(i)
            print("Address {} OK".format(ip))
    print(flag)

if __name__ == "__main__":
    execute()