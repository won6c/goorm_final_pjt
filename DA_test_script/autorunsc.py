import os
import subprocess
import csv

def autorunsc():
    tool_path = os.path.join(os.getcwd(), "..", "SysinternalsSuite\\")
    tool = "autorunsc64.exe"
    tool = os.path.join(tool_path,tool)
    print(tool)
    try:
        process = subprocess.Popen([tool,"-a","*","-c","-o","autorunsc_output.csv"])
        process.wait()
    except Exception as e:
        print(e)
        exit(1)
    read_csv()

def read_csv():
    file = os.path.join(os.getcwd(),"autorunsc_output.csv")
    with open(file,newline='') as f:
        reader = csv.reader(f,delimiter=',')

        for row in reader:
            print(row)

def main():
    autorunsc()

if __name__=="__main__":
    main()