import os
import subprocess

def regshot_current_status():
    tool_path = "C:\\Users\\User\\Desktop\\test\\Regshot_cli"
    tool = "Regshot_cmd-x64-ANSI.exe"
    tool = os.path.join(tool_path,tool)
    try:
        process = subprocess.Popen([tool,"current_status.hivu"])#,stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        process.wait()
    except Exception as e:
        print(e)
        exit(1)

def compare_with_currnet_status_output():
    tool_path = "C:\\Users\\User\\Desktop\\test\\Regshot_cli"
    tool = "Regshot_cmd-x64-ANSI.exe"
    tool = os.path.join(tool_path,tool)
    try:
        process = subprocess.Popen([tool,"current_status.hivu","-C"])#,stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        process.wait()
    except Exception as e:
        print(e)
        exit(1)

def main():
    regshot_current_status()
    compare_with_currnet_status_output()

if __name__=="__main__":
    main()